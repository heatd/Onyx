/*
 * Copyright (c) 2020 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_PACKETBUF_H
#define _ONYX_PACKETBUF_H

#include <stddef.h>

#include <onyx/iovec_iter.h>
#include <onyx/limits.h>
#include <onyx/net/inet_route.h>
#include <onyx/page.h>
#include <onyx/page_iov.h>

#define PACKETBUF_MAX_NR_PAGES (((UINT16_MAX + 1) / PAGE_SIZE) + 1)

#define DEFAULT_HEADER_LEN 128

struct vm_object;

#define PACKETBUF_GSO_TSO4 (1 << 0)
#define PACKETBUF_GSO_TSO6 (1 << 1)
#define PACKETBUF_GSO_UFO  (1 << 2)

struct tcp_packetbuf_info
{
    u32 seq, seq_len;
};

struct packetbuf;
__BEGIN_CDECLS
void pbf_free(struct packetbuf *pbf);
__END_CDECLS
/**
 * @brief The packetbuf is the data structure used to transport data up and
 * down the network stack. Its design is inspired by linux's sk_buff but adapted
 * to be more versatile and easier to use from the driver's point of view, by adopting
 * a full page_iov design.
 *
 * The packetbuf consists of two areas:
 *
 * 1) The head area: This is corresponds to the first page_vec entry and is directly
 *    accessible by put() and push_header(). The headers' placement is limited by the head area.
 *
 * 2) The data area: This corresponds to the rest of the page_vec and holds any data that doesn't
 *    fit in the head area.
 *
 *
 * Future design considerations:
 * 1) Future implementations of zero copy networking may need to reserve the first iov. It is then
 *    unclear if there are going to limitations in the packet's physical fragmentation of memory.
 *
 * 2) The packetbufs don't yet account for memory. It's noteworthy that packetbufs have huge
 * internal fragmentation, since every page_iov has a single PAGE_SIZE'd page that may consume a lot
 * more memory than the actual packet's size. We should either: 1) Ignore any wastefulness(provides
 * less accurate bookkeeping) or 2) Add some kmalloc-like-thing that allocates a chunk of physically
 * contiguous memory. This would possibly require a new page allocator in an efficient
 * implementation.
 *
 */
struct packetbuf
{
    /* Reasoning behind this - We're going to need at
     * most 64KiB of space for the buffer, since that's the most we'll
     * be able to buffer in one packet, for mostly technical but also practical reasons.
     * So, we're getting 'x' number of iovs for the packet's data and 2 more;
     * 1 is used as header data, because IF we're using zero-copy networking
     * there will be inevitably a gap between the headers(which should span at most from
     * [0 ... 120's...] and the end of the page.
     * The other iov is used as a terminating canary.
     */
    unsigned int refcount;

#define PBF_PAGE_IOVS PACKETBUF_MAX_NR_PAGES + 2
    struct page_iov page_vec[PBF_PAGE_IOVS];

    unsigned char *phy_header;
    unsigned char *link_header;
    unsigned char *net_header;
    unsigned char *transport_header;
    unsigned char *data;
    unsigned char *tail;
    unsigned char *end;

    void *buffer_start;

    uint16_t *csum_offset;
    unsigned char *csum_start;

    unsigned int header_length;
    uint16_t gso_size;

    uint8_t gso_flags;

    unsigned int needs_csum : 1;
    unsigned int zero_copy : 1;
    int domain;

    struct list_head list_node;

    union {
        struct inet_route route;
    };

    union {
        struct tcp_packetbuf_info tpi;
    };

#ifdef __cplusplus
    /**
     * @brief Construct a new default packetbuf object.
     *
     */
    packetbuf()
        : refcount{1}, page_vec{}, phy_header{}, link_header{}, net_header{}, transport_header{},
          data{}, tail{}, end{}, buffer_start{}, csum_offset{nullptr}, csum_start{nullptr},
          header_length{}, gso_size{}, gso_flags{}, needs_csum{0}, zero_copy{0}, domain{0}
    {
    }

    /**
     * @brief Destroy the packetbuf object and free the backing pages.s
     *
     */
    ~packetbuf();

    void *operator new(size_t length);
    void operator delete(void *ptr);

    void *operator new(size_t length, void *ptr)
    {
        return ptr;
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
    bool allocate_space(size_t length);

    /**
     * @brief Reserve space for the headers.
     *
     * @param header_length Length of the headers
     */
    void reserve_headers(unsigned int header_length);

    /**
     * @brief Get space for a networking header, and adjust data to point to the start of the
     * header.
     *
     * @param size Size of the header.
     *
     * @return void* The address of the new header.
     */
    void *push_header(unsigned int size);

    /**
     * @brief Get space for data, and advance tail by size.
     *
     * @param size The length of the data.
     *
     * @return void* The address of the new data.
     */
    void *put(unsigned int size);

    /**
     * @brief Calculates the total length of the buffer.
     *
     * @return The length of the packetbuf, in bytes.
     */
    unsigned int length() const
    {
        unsigned int out_of_data_area = 0;

        for (const auto &v : page_vec)
        {
            if (&v == (page_iov *) &page_vec)
                continue;
            if (!v.page)
                break;

            out_of_data_area += v.length;
        }

        return (tail - data) + out_of_data_area;
    }

    /**
     * @brief Calculates the offset of the transport header, from the start
     * of the packet.
     *
     * @return Offset of the transport header.
     */
    unsigned int transport_header_off() const
    {
        return transport_header - data;
    }

    /**
     * @brief Calculates the offset of the network header, from the start
     * of the packet.
     *
     * @return Offset of the network header.
     */
    unsigned int net_header_off() const
    {
        return net_header - data;
    }

    /**
     * @brief Calculates the offset of the checksum field in the packet, for
     * checksum offloading purposes.
     *
     * @return Offset of the checksum field.
     */
    unsigned int csum_offset_bytes() const
    {
        return (unsigned char *) csum_offset - data;
    }

    /**
     * @brief Calculates the offset of the start of the packet from the start of
     * the first page.
     *
     * @return Offset of the start of the packet.
     */
    unsigned int start_page_off() const
    {
        return data - (unsigned char *) buffer_start;
    }

    /**
     * @brief Expands the packet buffer, either by doing put(), expanding page iters, or adding new
     * pages.
     *
     * @param ubuf User address of the buffer.
     * @param len Length of the buffer.
     * @return The amount copied, or a negative error code if we failed to copy anything.
     */
    ssize_t expand_buffer(const void *ubuf, unsigned int len);

    /**
     * @brief Counts all valid page vector entries.
     *
     * @return Number of valid page vector entries in the packetbuf.
     */
    unsigned int count_page_vecs() const
    {
        for (unsigned int i = 0; i < PACKETBUF_MAX_NR_PAGES + 1; i++)
        {
            if (!page_vec[i].page)
                return i;
        }

        __builtin_unreachable();
    }

#define PBF_COPY_ITER_PEEK (1 << 0)

    /**
     * @brief Copy the packetbuf (or whatever is left of it) to iter
     *
     * @param iter iovec iterator (in-out parameter)
     * @param flags Copy iter flags
     *
     * @return Number of bytes copied, or negative error code
     */
    ssize_t copy_iter(iovec_iter &iter, unsigned int flags);

    void ref()
    {
        __atomic_add_fetch(&refcount, 1, __ATOMIC_RELAXED);
    }

    void unref()
    {
        if (__atomic_sub_fetch(&refcount, 1, __ATOMIC_RELAXED) == 0)
            pbf_free(this);
    }
#endif
};

__BEGIN_CDECLS

/**
 * @brief Clones a packetbuf and returns a metadata-identical and data-identical copy.
 *
 * @param original The original packetbuf.
 * @return The new packetbuf, or NULL if we ran out of memory.
 */
struct packetbuf *packetbuf_clone(struct packetbuf *original);

static inline bool pbf_can_try_put(struct packetbuf *pbf)
{
    /* Using put with other page vecs is bound to break something */
    return pbf->page_vec[1].page == nullptr;
}

static inline unsigned int pbf_tail_room(struct packetbuf *pbf)
{
    return pbf->end - pbf->tail;
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
bool pbf_allocate_space(struct packetbuf *pbf, size_t length);

/**
 * @brief Reserve space for the headers.
 *
 * @param pbf Packetbuf
 * @param header_length Length of the headers
 */
static inline void pbf_reserve_headers(struct packetbuf *pbf, unsigned int header_length)
{
    pbf->data += header_length;
    pbf->tail = pbf->data;
}

/**
 * @brief Get space for a networking header, and adjust data to point to the start of the header.
 *
 * @param pbf Packetbuf
 * @param size Size of the header.
 *
 * @return void* The address of the new header.
 */
static inline void *pbf_push_header(struct packetbuf *pbf, unsigned int header_length)
{
    assert((unsigned long) pbf->data >= (unsigned long) pbf->buffer_start);
    pbf->data -= header_length;
    return (void *) pbf->data;
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
ssize_t pbf_expand_buffer(struct packetbuf *pbf, const void *ubuf_, unsigned int len);

/**
 * @brief Get space for data, and advance tail by size.
 *
 * @param pbf Packetbuf
 * @param size The length of the data.
 *
 * @return void* The address of the new data.
 */
static inline void *pbf_put(struct packetbuf *pbf, unsigned int size)
{
    void *ret = pbf->tail;
    pbf->tail += size;
    assert((unsigned long) pbf->tail <= (unsigned long) pbf->end);
    return ret;
}

/**
 * @brief Calculates the total length of the buffer.
 *
 * @param pbf Packetbuf
 * @return The length of the packetbuf, in bytes.
 */
static inline unsigned int pbf_length(struct packetbuf *pbf)
{
    unsigned int out_of_data_area = 0;

    for (unsigned long i = 1; i < PBF_PAGE_IOVS; i++)
    {
        if (!pbf->page_vec[i].page)
            break;

        out_of_data_area += pbf->page_vec[i].length;
    }

    return (pbf->tail - pbf->data) + out_of_data_area;
}

static inline void pbf_get(struct packetbuf *pbf)
{
    __atomic_add_fetch(&pbf->refcount, 1, __ATOMIC_RELAXED);
}

static inline void pbf_put_ref(struct packetbuf *pbf)
{
    if (__atomic_sub_fetch(&pbf->refcount, 1, __ATOMIC_RELAXED) == 0)
        pbf_free(pbf);
}

typedef unsigned int gfp_t;

struct packetbuf *pbf_alloc(gfp_t gfp);

__END_CDECLS

#define PACKET_MAX_HEAD_LENGTH 128

#endif
