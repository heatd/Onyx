/*
 * Copyright (c) 2020 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <onyx/compiler.h>
#include <onyx/kunit.h>
#include <onyx/local_lock.h>
#include <onyx/mm/slab.h>
#include <onyx/mm/vm_object.h>
#include <onyx/net/socket.h>
#include <onyx/new.h>
#include <onyx/packetbuf.h>
#include <onyx/refcount.h>

#include <onyx/memory.hpp>

static struct slab_cache *packetbuf_cache;

static __init void packetbuf_init_cache()
{
    packetbuf_cache = kmem_cache_create("packetbuf", sizeof(packetbuf), alignof(packetbuf),
                                        SLAB_PANIC | KMEM_CACHE_HWALIGN, nullptr);
}

void *packetbuf::operator new(size_t length)
{
    /* TODO: DO NOT GFP_ATOMIC PLEASE */
    return kmem_cache_alloc(packetbuf_cache, GFP_ATOMIC);
}

void packetbuf::operator delete(void *ptr)
{
    kmem_cache_free(packetbuf_cache, ptr);
}

/**
 * @brief Reserve space for the packet.
 * This function is only meant to be called once, at initialisation,
 * and calling it again may make the kernel crash and burn.
 *
 * @param pbf Packetbuf
 * @param length The maximum length of the whole packet(including headers and footers)
 *
 * @return Returns true if it was successful, false if it was not.
 */
bool pbf_allocate_space(struct packetbuf *pbf, size_t length)
{
    /* This should only be called once - essentially,
     * we allocate enough pages for the packet and fill page_vec.
     */

    auto nr_pages = vm_size_to_pages(length);

    page *pages = alloc_page_list(nr_pages, PAGE_ALLOC_NO_ZERO);
    if (!pages)
        return false;

    auto pages_head = pages;

    for (size_t i = 0; i < nr_pages; i++)
    {
        pbf->page_vec[i].page = pages;

        if (i == 0)
            pbf->page_vec[i].length = min(length, PAGE_SIZE);
        else
            pbf->page_vec[i].length = 0;

        length -= pbf->page_vec[i].length;
        pbf->page_vec[i].page_off = 0;
        pages = pages->next_un.next_allocation;
    }

    pbf->buffer_start = PAGE_TO_VIRT(pages_head);
    pbf->net_header = pbf->transport_header = nullptr;
    pbf->data = pbf->tail = (unsigned char *) pbf->buffer_start;
    pbf->end = (unsigned char *) pbf->buffer_start + PAGE_SIZE;
    pbf->nr_vecs = nr_pages;

    return true;
}

/**
 * @brief Reserve space for the packet.
 * This function is only meant to be called once, at initialisation,
 * and calling it again may make the kernel crash and burn.
 *
 * @param length The maximum length of the whole packet(including headers and footers)
 *
 * @return Returns true if it was successful, false if it was not.
 */
bool packetbuf::allocate_space(size_t length)
{
    return pbf_allocate_space(this, length);
}

/**
 * @brief Reserve space for the headers.
 *
 * @param header_length Length of the headers
 */
void packetbuf::reserve_headers(unsigned int header_length)
{
    pbf_reserve_headers(this, header_length);
}

/**
 * @brief Get space for a networking header, and adjust data to point to the start of the header.
 *
 * @param size Size of the header.
 *
 * @return void* The address of the new header.
 */
void *packetbuf::push_header(unsigned int header_length)
{
    return pbf_push_header(this, header_length);
}

/**
 * @brief Get space for data, and advance tail by size.
 *
 * @param size The length of the data.
 *
 * @return void* The address of the new data.
 */
void *packetbuf::put(unsigned int size)
{
    return pbf_put(this, size);
}

/**
 * @brief Destroy the packetbuf object and free the backing pages.s
 *
 */
packetbuf::~packetbuf()
{
    if (dtor)
        dtor(this);
    for (auto &v : page_vec)
    {
        if (v.page)
            free_page(v.page);
    }
}

/**
 * @brief Clones a packetbuf and returns a metadata-identical and data-identical copy.
 *
 * @param original The original packetbuf.
 * @return The new packetbuf, or NULL if we ran out of memory.
 */
packetbuf *packetbuf_clone(packetbuf *original)
{
    unique_ptr buf = make_unique<packetbuf>();
    if (!buf)
        return nullptr;

    for (size_t i = 0; i < PACKETBUF_MAX_NR_PAGES + 2; i++)
    {
        struct page_iov &vec = original->page_vec[i];
        if (vec.page)
            page_ref(vec.page);
        buf->page_vec[i] = vec;
    }

    buf->buffer_start = original->buffer_start;
    buf->end = original->end;
    buf->data = original->data;
    buf->tail = original->tail;
    buf->net_header = original->net_header;
    buf->transport_header = original->transport_header;
    buf->link_header = original->link_header;
    buf->phy_header = original->phy_header;
    buf->domain = original->domain;
    buf->route = original->route;
    buf->tpi = original->tpi;
    buf->nr_vecs = original->nr_vecs;
    buf->total_len = original->total_len;

    return buf.release();
}

static int allocate_page_vec(page_iov &v)
{
    page *p = alloc_page(0);

    if (!p)
        return -ENOMEM;

    v.length = 0;
    v.page = p;
    v.page_off = 0;

    return 0;
}

ssize_t copy_to_pbf(struct packetbuf *pbf, iovec_iter *iter)
{
    ssize_t ret = 0, st;
    unsigned int tail_room;
    /* Right now, trying to expand a packetbuf with zero copy enabled would blow up spectacularly,
     * since it could try to access random pages that may be allocated or something.
     */
    assert(!pbf->zero_copy);

    if (pbf_can_try_put(pbf))
    {
        tail_room = pbf_tail_room(pbf);
        if (tail_room > 0)
        {
            void *tail = pbf->tail;
            ret = copy_from_iter(iter, tail, tail_room);
            if (ret < 0)
                return ret;

            pbf->tail += ret;
            if (ret < tail_room)
                return ret;
        }
#if DEBUG_PACKETBUF_GROW
        printk("Put %ld bytes in put()\n", ret);
#endif
    }

    for (unsigned int i = 1; i < PACKETBUF_MAX_NR_PAGES; i++)
    {
        if (iter->empty())
            break;

        auto &v = pbf->page_vec[i];

        if (!v.page)
        {
            if (allocate_page_vec(v) < 0)
                return -ENOMEM;
        }

        tail_room = PAGE_SIZE - v.length;
        if (tail_room > 0)
        {
#if DEBUG_PACKETBUF_GROW
            printk("length %u + tail room %u = %u", length(), tail_room, length() + tail_room);
#endif
            u8 *dest_ptr = (u8 *) PAGE_TO_VIRT(v.page) + v.page_off + v.length;

            st = copy_from_iter(iter, dest_ptr, tail_room);
            if (st < 0)
            {
                if (!ret)
                    ret = st;
                break;
            }

#if DEBUG_PACKETBUF_GROW
            printk("Put %u bytes in page vec %u\n", to_put, i);
#endif

            v.length += st;
            ret += st;
        }
    }

    return ret;
}

/**
 * @brief Expands the packet buffer, either by doing put(), expanding page iters, or adding new
 * pages.
 *
 * @param pbf Packetbuf
 * @param ubuf User address of the buffer.
 * @param len Length of the buffer.
 * @return The amount copied, or a negative error code if we failed to copy anything.
 */
ssize_t pbf_expand_buffer(struct packetbuf *pbf, const void *ubuf_, unsigned int len)
{
    struct iovec iov;
    iov.iov_base = (void *) ubuf_;
    iov.iov_len = len;
    iovec_iter iter{{&iov, 1}, len};
    return copy_to_pbf(pbf, &iter);
}

/**
 * @brief Expands the packet buffer, either by doing put(), expanding page iters, or adding new
 * pages.
 *
 * @param ubuf User address of the buffer.
 * @param len Length of the buffer.
 * @return The amount copied, or a negative error code if we failed to copy anything.
 */
ssize_t packetbuf::expand_buffer(const void *ubuf, unsigned int len)
{
    return pbf_expand_buffer(this, ubuf, len);
}

/**
 * @brief Copy the packetbuf (or whatever is left of it) to iter
 *
 * @param iter iovec iterator (in-out parameter)
 * @param flags Copy iter flags
 *
 * @return Number of bytes copied, or negative error code
 */
ssize_t packetbuf::copy_iter(iovec_iter &iter, unsigned int flags)
{
    ssize_t copied = 0, st;
    unsigned int last_vec = 1;
    u8 *datap = data;
    size_t in_body_data = tail - datap;

    while (in_body_data)
    {
        if (iter.empty())
            break;

        st = copy_to_iter(&iter, datap, in_body_data);
        if (st < 0)
        {
            if (!copied)
                copied = -EFAULT;
            return copied;
        }

        datap += st;
        in_body_data -= st;
        copied += st;
        DCHECK(datap <= tail);

        if (!(flags & PBF_COPY_ITER_PEEK))
            data = datap;
    }

    if (copied < 0)
        return copied;

    // Used for page_iov iteration, to avoid messing with vec if PBF_COPY_ITER_PEEK
    unsigned int current_iov_len = page_vec[1].length;
    unsigned int current_iov_off = 0;

    while (!iter.empty())
    {
        ssize_t to_copy = 0;
        void *ptr = nullptr;
        struct page_iov *vec = nullptr;

        for (; last_vec < PACKETBUF_MAX_NR_PAGES + 1;
             last_vec++, current_iov_len = page_vec[last_vec].length, current_iov_off = 0)
        {
            // Skip the first vec
            if (last_vec == 0)
                continue;

            // We reached the end
            if (!page_vec[last_vec].page)
                goto out;

            // Empty iov
            if (current_iov_len == 0)
                continue;

            vec = &page_vec[last_vec];
            to_copy = current_iov_len;
            ptr = (u8 *) (PAGE_TO_VIRT(vec->page)) + vec->page_off + current_iov_off;
            break;
        }

        if (!vec)
            break;

        st = copy_to_iter(&iter, ptr, to_copy);
        if (st < 0)
        {
            if (!copied)
                copied = -EFAULT;
            break;
        }

        current_iov_len -= st;
        current_iov_off += st;
        copied += st;

        if (!(flags & PBF_COPY_ITER_PEEK))
        {
            // Adjust the page_iov
            vec->page_off += st;
            vec->length -= st;
            current_iov_off = 0;
            DCHECK(vec->page_off <= PAGE_SIZE);
            DCHECK(vec->length <= PAGE_SIZE);
            DCHECK(vec->page_off + vec->length <= PAGE_SIZE);
        }
    }

out:
    return copied;
}

void pbf_free(struct packetbuf *pbf)
{
    pbf->~packetbuf();
    kmem_cache_free(packetbuf_cache, pbf);
}

struct packetbuf *pbf_alloc(gfp_t gfp)
{
    struct packetbuf *pbf = (struct packetbuf *) kmem_cache_alloc(packetbuf_cache, gfp);
    if (!pbf)
        return nullptr;
    new (pbf) struct packetbuf;
    return pbf;
}

struct packetbuf *pbf_alloc_sk(gfp_t gfp, struct socket *sock, unsigned int len)
{
    struct page_frag f;
    struct packetbuf *pbf;

    pbf = pbf_alloc(gfp);
    if (!pbf)
        return NULL;

    len = ALIGN_TO(len, 4);
    if (page_frag_alloc(&sock->sock_pfi, len, gfp, &f) < 0)
    {
        pbf_free(pbf);
        return NULL;
    }

    pbf->page_vec[0].page = f.page;
    pbf->page_vec[0].page_off = f.offset;
    pbf->page_vec[0].length = f.len;

    pbf->buffer_start = (char *) PAGE_TO_VIRT(f.page) + f.offset;
    pbf->net_header = pbf->transport_header = NULL;
    pbf->data = pbf->tail = (unsigned char *) pbf->buffer_start;
    pbf->end = (unsigned char *) pbf->buffer_start + f.len;
    pbf->sock = sock;
    pbf->total_len = sizeof(struct packetbuf) + f.len;
    pbf->nr_vecs = 1;

    return pbf;
}

struct pbf_pcpu_rx_data
{
    struct page_frag_info pfi;
};

static PER_CPU_VAR(struct pbf_pcpu_rx_data pcpu_rx_data);
static struct local_lock pcpu_rx_lock;

struct packetbuf *pbf_alloc_rx(gfp_t gfp, unsigned int len)
{
    struct page_frag f;
    struct packetbuf *pbf;
    struct pbf_pcpu_rx_data *rx;

    pbf = pbf_alloc(gfp);
    if (!pbf)
        return NULL;

    local_lock(&pcpu_rx_lock);
    rx = get_per_cpu_ptr(pcpu_rx_data);

    len = ALIGN_TO(len, 4);
    if (page_frag_alloc(&rx->pfi, len, gfp, &f) < 0)
    {
        pbf_free(pbf);
        local_unlock(&pcpu_rx_lock);
        return NULL;
    }

    local_unlock(&pcpu_rx_lock);

    pbf->page_vec[0].page = f.page;
    pbf->page_vec[0].page_off = f.offset;
    pbf->page_vec[0].length = f.len;

    pbf->buffer_start = (char *) PAGE_TO_VIRT(f.page) + f.offset;
    pbf->net_header = pbf->transport_header = NULL;
    pbf->data = pbf->tail = (unsigned char *) pbf->buffer_start;
    pbf->end = (unsigned char *) pbf->buffer_start + f.len;
    pbf->total_len = sizeof(struct packetbuf) + f.len;
    pbf->nr_vecs = 1;

    return pbf;
}

#ifdef CONFIG_KUNIT

static ref_guard<packetbuf> alloc_pbf(unsigned int length)
{
    ref_guard<packetbuf> buf = make_refc<packetbuf>();
    CHECK(buf);
    CHECK(buf->allocate_space(length));

    {
        auto_addr_limit a{VM_KERNEL_ADDR_LIMIT};
        char cbuf[1000];
        memset(cbuf, 'A', sizeof(buf));

        while (length)
        {
            ssize_t to_add = min(sizeof(cbuf), (size_t) length);
            CHECK(buf->expand_buffer(cbuf, to_add) == to_add);
            length -= to_add;
        }
    }

    return buf;
}

TEST(packetbuf, copy_iter_only_body)
{
    // Test if copy_iter correctly handles body copies
    unique_page page = alloc_page(GFP_KERNEL);
    CHECK(page.get() != nullptr);

    auto_addr_limit a{VM_KERNEL_ADDR_LIMIT};
    ref_guard<packetbuf> buf = alloc_pbf(PAGE_SIZE);

    struct iovec v;
    v.iov_base = PAGE_TO_VIRT(page.get());
    v.iov_len = PAGE_SIZE;
    iovec_iter it{{&v, 1}, PAGE_SIZE};

    ASSERT_EQ((ssize_t) PAGE_SIZE, buf->copy_iter(it, 0));

    it = {{&v, 1}, PAGE_SIZE};
    // Should return nothing now (should be empty!)
    EXPECT_EQ(0L, buf->copy_iter(it, 0));
}

TEST(packetbuf, copy_iter_peek_body)
{
    // Test if copy_iter correctly handles body copies with MSG_PEEK handling
    unique_page page = alloc_page(GFP_KERNEL);
    CHECK(page.get() != nullptr);

    auto_addr_limit a{VM_KERNEL_ADDR_LIMIT};
    ref_guard<packetbuf> buf = alloc_pbf(PAGE_SIZE);

    struct iovec v;
    v.iov_base = PAGE_TO_VIRT(page.get());
    v.iov_len = PAGE_SIZE;
    iovec_iter it{{&v, 1}, PAGE_SIZE};

    ASSERT_EQ((ssize_t) PAGE_SIZE, buf->copy_iter(it, PBF_COPY_ITER_PEEK));
    it = {{&v, 1}, PAGE_SIZE};
    // Should not have discarded anything now
    EXPECT_EQ((ssize_t) PAGE_SIZE, buf->copy_iter(it, 0));
}

TEST(packetbuf, copy_iter_peek_page_iov)
{
    // Test if copy_iter correctly handles body + page_iov copies with MSG_PEEK handling
    unique_page page = alloc_pages(2, GFP_KERNEL);
    CHECK(page.get() != nullptr);

    auto_addr_limit a{VM_KERNEL_ADDR_LIMIT};
    ref_guard<packetbuf> buf = alloc_pbf(PAGE_SIZE * 4);

    struct iovec v;
    v.iov_base = PAGE_TO_VIRT(page.get());
    v.iov_len = PAGE_SIZE << 2;
    iovec_iter it{{&v, 1}, PAGE_SIZE << 2};

    ASSERT_EQ((ssize_t) PAGE_SIZE << 2, buf->copy_iter(it, PBF_COPY_ITER_PEEK));
    it = {{&v, 1}, PAGE_SIZE << 2};
    // Should not have discarded anything now
    EXPECT_EQ((ssize_t) PAGE_SIZE << 2, buf->copy_iter(it, 0));
    it = {{&v, 1}, PAGE_SIZE << 2};
    EXPECT_EQ(0L, buf->copy_iter(it, 0));
}

TEST(packetbuf, copy_iter_page_iov_partial)
{
    // Test if copy_iter correctly handles partial page_iov copies
    unique_page page = alloc_pages(1, GFP_KERNEL);
    CHECK(page.get() != nullptr);

    auto_addr_limit a{VM_KERNEL_ADDR_LIMIT};
    ref_guard<packetbuf> buf = alloc_pbf(PAGE_SIZE * 4);

    struct iovec v;
    v.iov_base = PAGE_TO_VIRT(page.get());
    v.iov_len = PAGE_SIZE << 1;
    iovec_iter it{{&v, 1}, PAGE_SIZE << 1};

    ASSERT_EQ((ssize_t) PAGE_SIZE << 1, buf->copy_iter(it, 0));
    it = {{&v, 1}, PAGE_SIZE << 1};
    // Should not have discarded anything now
    EXPECT_EQ((ssize_t) PAGE_SIZE << 1, buf->copy_iter(it, 0));
    it = {{&v, 1}, PAGE_SIZE << 1};
    EXPECT_EQ(0L, buf->copy_iter(it, 0));
}

#endif
