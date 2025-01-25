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
    // printk("len %u\n", len);
    ssize_t ret = 0;
    const uint8_t *ubuf = static_cast<const uint8_t *>(ubuf_);
    /* Right now, trying to expand a packetbuf with zero copy enabled would blow up spectacularly,
     * since it could try to access random pages that may be allocated or something.
     */
    assert(!pbf->zero_copy);

    if (pbf_can_try_put(pbf))
    {
        if (pbf_tail_room(pbf))
        {
            auto to_put = min(pbf_tail_room(pbf), len);
            auto p = pbf_put(pbf, to_put);

            if (copy_from_user(p, ubuf, to_put) < 0)
                return -EFAULT;

            ubuf += to_put;
            len -= to_put;
            ret += to_put;
        }
#if DEBUG_PACKETBUF_GROW
        printk("Put %ld bytes in put()\n", ret);
#endif
    }

    for (unsigned int i = 1; i < PACKETBUF_MAX_NR_PAGES; i++)
    {
        if (!len)
            break;

        auto &v = pbf->page_vec[i];

        if (!v.page)
        {
            if (allocate_page_vec(v) < 0)
                return -ENOMEM;
        }

        unsigned int tail_room = PAGE_SIZE - v.length;

        if (tail_room > 0)
        {
            auto to_put = min(tail_room, len);

#if DEBUG_PACKETBUF_GROW
            printk("length %u + tail room %u = %u", length(), tail_room, length() + tail_room);
#endif
            uint8_t *dest_ptr = (uint8_t *) PAGE_TO_VIRT(v.page) + v.page_off + v.length;

            if (copy_from_user(dest_ptr, ubuf, to_put) < 0)
                return -EFAULT;
#if DEBUG_PACKETBUF_GROW
            printk("Put %u bytes in page vec %u\n", to_put, i);
#endif

            v.length += to_put;
            ubuf += to_put;
            len -= to_put;
            ret += to_put;
        }
    }

    return ret;
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
    ssize_t copied = 0;
    unsigned int last_vec = 1;
    u8 *datap = data;
    size_t in_body_data = tail - datap;

    while (in_body_data)
    {
        if (iter.empty())
            break;
        auto iov = iter.curiovec();
        size_t to_copy = min(iov.iov_len, in_body_data);

        if (copy_to_user(iov.iov_base, datap, to_copy) < 0)
        {
            if (!copied)
                copied = -EFAULT;
            return copied;
        }

        datap += to_copy;
        in_body_data -= to_copy;
        copied += to_copy;
        iter.advance(copied);
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
        auto iov = iter.curiovec();
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
            to_copy = min(iov.iov_len, (size_t) current_iov_len);
            ptr = (u8 *) (PAGE_TO_VIRT(vec->page)) + vec->page_off + current_iov_off;
            break;
        }

        if (!vec)
            break;

        if (copy_to_user(iov.iov_base, ptr, to_copy) < 0)
        {
            if (!copied)
                copied = -EFAULT;
            break;
        }

        current_iov_len -= to_copy;
        current_iov_off += to_copy;
        copied += to_copy;
        iter.advance(to_copy);

        if (!(flags & PBF_COPY_ITER_PEEK))
        {
            // Adjust the page_iov
            vec->page_off += to_copy;
            vec->length -= to_copy;
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
