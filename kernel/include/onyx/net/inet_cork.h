/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_NET_INET_CORK_H
#define _ONYX_NET_INET_CORK_H

#include <stddef.h>

#include <onyx/list.h>
#include <onyx/net/inet_packet_flow.h>
#include <onyx/packetbuf.h>

#include <uapi/posix-types.h>

class inet_cork
{
protected:
    list_head packet_list;
    size_t packet_list_len;
    int pending_;
    size_t length_;

    // Needed so we can check whether or not to let us have more datagrams
    int sock_type;

    int alloc_and_append(const iovec *vec, size_t vec_len, size_t proto_hdr_len,
                         size_t max_packet_len, size_t skip_first);

public:
    inet_cork(int sock_type) : pending_{AF_UNSPEC}, length_{}, sock_type{sock_type}
    {
        INIT_LIST_HEAD(&packet_list);
    }

    ~inet_cork();

    int append_data(const iovec *vec, size_t vec_len, size_t proto_hdr_size, size_t max_packet_len);

    int send(const iflow &flow, void (*prepare_headers)(packetbuf *buf, const iflow &flow));

    list_head *get_packet_list()
    {
        return &packet_list;
    }

    int &pending()
    {
        return pending_;
    }

    size_t length() const
    {
        return length_;
    }

    /**
     * @brief Append a whole packetbuf to the end of the list
     *        Note: Increments buf's reference count
     *
     * @param buf Packetbuf to append
     */
    void append_packet(packetbuf *buf)
    {
        packet_list_len++;
        list_add_tail(&buf->list_node, &packet_list);
    }
};

#endif
