/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_NET_ICMP_H
#define _ONYX_NET_ICMP_H

#include <stdint.h>

#include <onyx/cred.h>
#include <onyx/net/inet_socket.h>
#include <onyx/net/ip.h>
#include <onyx/net/netif.h>
#include <onyx/scoped_lock.h>

#include <uapi/icmp.h>

#include <onyx/expected.hpp>

#define ICMP_TYPE_ECHO_REPLY         0
#define ICMP_TYPE_DEST_UNREACHABLE   3
#define ICMP_TYPE_SOURCE_QUENCH      4
#define ICMP_TYPE_REDIRECT_MSG       5
#define ICMP_TYPE_ECHO_REQUEST       8
#define ICMP_TYPE_ROUTER_AD          9
#define ICMP_TYPE_ROUTER_SOLICIT     10
#define ICMP_TYPE_TIME_EXCEEDED      11
#define ICMP_TYPE_BAD_IP_HEADER      12
#define ICMP_TYPE_TIMESTAMP          13
#define ICMP_TYPE_TIMESTAMP_REPLY    14
#define ICMP_TYPE_INFO_REQUEST       15
#define ICMP_TYPE_INFO_REPLY         16
#define ICMP_TYPE_ADDRESS_MASK_REQ   17
#define ICMP_TYPE_ADDRESS_MASK_REPLY 18

/* For ICMP_TYPE_DEST_UNREACHABLE */
#define ICMP_CODE_NET_UNREACHABLE        0
#define ICMP_CODE_HOST_UNREACHABLE       1
#define ICMP_CODE_PROTO_UNREACHABLE      2
#define ICMP_CODE_PORT_UNREACHABLE       3
#define ICMP_CODE_FRAGMENTATION_REQUIRED 4
#define ICMP_CODE_SOURCE_ROUTE_FAILED    5

namespace icmp
{

struct icmp_header
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest;
    union {
        /* ICMP destination unreachable packets contain the original
         * IP header + 8 bytes of the original datagram.
         */
        struct
        {
            struct ip_header header;
            unsigned char original_dgram[8];
        } dest_unreach;

        struct
        {
            uint8_t data[0];
        } echo;
    };
} __attribute__((packed));

struct dst_unreachable_info
{
    uint8_t code;
    uint16_t next_hop_mtu;
    const unsigned char *dgram;
    const ip_header *iphdr;

    dst_unreachable_info()
    {
    }
    dst_unreachable_info(uint8_t code, uint16_t next_hop_mtu, const unsigned char *dgram,
                         const ip_header *iphdr)
        : code{code}, next_hop_mtu{next_hop_mtu}, dgram{dgram}, iphdr{iphdr}
    {
    }
};

extern const socket_ops icmp_ops;

class icmp_socket : public inet_socket
{
private:
    static constexpr unsigned int icmp_max_filters = 5;
    spinlock filters_lock;
    cul::vector<icmp_filter> filters;

    int add_filter(icmp_filter &&f);

    packetbuf *get_rx_head()
    {
        if (list_is_empty(&rx_packet_list))
            return nullptr;

        return container_of(list_first_element(&rx_packet_list), packetbuf, list_node);
    }

    bool has_data_available()
    {
        return !list_is_empty(&rx_packet_list);
    }

    expected<packetbuf *, int> get_datagram(int flags);

    int wait_for_dgrams()
    {
        return wait_for_event_socklocked_interruptible(&rx_wq, !list_is_empty(&rx_packet_list));
    }

public:
    icmp_socket() : filters_lock{}, filters{}
    {
        spinlock_init(&filters_lock);
        sock_ops = &icmp_ops;
    }

    ~icmp_socket() = default;

    int bind(struct sockaddr *addr, socklen_t addrlen);
    int connect(struct sockaddr *addr, socklen_t addrlen, int flags);
    ssize_t sendmsg(const struct msghdr *msg, int flags);
    int getsockopt(int level, int optname, void *val, socklen_t *len);
    int setsockopt(int level, int optname, const void *val, socklen_t len);
    short poll(void *poll_file, short events);
    ssize_t recvmsg(msghdr *msg, int flags);

    bool match_filter(const icmp_header *header)
    {
        scoped_lock g{filters_lock};

        for (const auto &f : filters)
        {
            if (header->type != f.type && f.type != ICMP_FILTER_TYPE_UNSPEC)
                continue;
            if (header->code != f.code && f.code != ICMP_FILTER_CODE_UNSPEC)
                continue;

            return true;
        }

        return false;
    }

    void rx_dgram(packetbuf *buf);

    /**
     * @brief Handle ICMP socket backlog
     *
     */
    void handle_backlog();
};

icmp_socket *create_socket(int type);

static constexpr unsigned int min_icmp_size()
{
    return 8;
}

int handle_packet(const inet_route &route, packetbuf *buf);

int send_dst_unreachable(const dst_unreachable_info &info, netif *nif);

} // namespace icmp

#endif
