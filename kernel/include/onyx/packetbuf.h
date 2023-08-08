/*
 * Copyright (c) 2020 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_PACKETBUF_H
#define _ONYX_PACKETBUF_H

#include <stddef.h>

#include <onyx/iovec_iter.h>
#include <onyx/limits.h>
#include <onyx/net/inet_route.h>
#include <onyx/page.h>
#include <onyx/page_iov.h>
#include <onyx/refcount.h>

#define PACKETBUF_MAX_NR_PAGES (((UINT16_MAX + 1) / PAGE_SIZE) + 1)

#define DEFAULT_HEADER_LEN 128

struct vm_object;

#define PACKETBUF_GSO_TSO4 (1 << 0)
#define PACKETBUF_GSO_TSO6 (1 << 1)
#define PACKETBUF_GSO_UFO  (1 << 2)

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
struct packetbuf : public refcountable
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

    struct page_iov page_vec[PACKETBUF_MAX_NR_PAGES + 2];

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
    vm_object *vmo;

    unsigned int header_length;
    uint16_t gso_size;

    uint8_t gso_flags;

    unsigned int needs_csum : 1;
    unsigned int zero_copy : 1;
    int domain;

    list_head_cpp<packetbuf> list_node;

    union {
        inet_route route;
    };

private:
    /* Using put with other page vecs is bound to break something */
    bool can_try_put() const
    {
        return page_vec[1].page == nullptr;
    }

    unsigned int tail_room() const
    {
        return end - tail;
    }

public:
    /**
     * @brief Construct a new default packetbuf object.
     *
     */
    packetbuf()
        : refcountable{}, page_vec{}, phy_header{}, link_header{}, net_header{},
          transport_header{}, data{}, tail{}, end{}, buffer_start{}, csum_offset{nullptr},
          csum_start{nullptr}, vmo{}, header_length{}, gso_size{}, gso_flags{},
          needs_csum{0}, zero_copy{0}, domain{0}, list_node{this}
    {
    }

    /**
     * @brief Destroy the packetbuf object and free the backing pages.s
     *
     */
    ~packetbuf();

    void *operator new(size_t length);
    void operator delete(void *ptr);

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
};

/**
 * @brief Clones a packetbuf and returns a metadata-identical and data-identical copy.
 *
 * @param original The original packetbuf.
 * @return The new packetbuf, or NULL if we ran out of memory.
 */
packetbuf *packetbuf_clone(packetbuf *original);

#define PACKET_MAX_HEAD_LENGTH 128

#endif
