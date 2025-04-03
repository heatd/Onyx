/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_NET_ICMPV6_H
#define _ONYX_NET_ICMPV6_H

#include <stddef.h>
#include <stdint.h>

#include <onyx/net/inet_route.h>
#include <onyx/net/inet_socket.h>
#include <onyx/scoped_lock.h>
#include <onyx/spinlock.h>

#include <uapi/icmp.h>

#define ICMPV6_DEST_UNREACHABLE  1
#define ICMPV6_PACKET_TOO_BIG    2
#define ICMPV6_TIME_EXCEEDED     3
#define ICMPV6_PARAMETER_PROBLEM 4
#define ICMPV6_ECHO_REQUEST      128
#define ICMPV6_ECHO_REPLY        129
#define ICMPV6_ROUTER_SOLICIT    133
#define ICMPV6_ROUTER_ADVERT     134
#define ICMPV6_NEIGHBOUR_SOLICIT 135
#define ICMPV6_NEIGHBOUR_ADVERT  136
#define ICMPV6_MLDV2_REPORT_MSG  143

struct icmpv6_header
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t data;
} __attribute__((packed));

namespace icmpv6
{

struct send_data
{
    uint8_t type;
    uint8_t code;
    const inet_route &route;
    uint32_t data;

    send_data(uint8_t t, uint8_t c, const inet_route &r, uint32_t data)
        : type{t}, code{c}, route{r}, data{data}
    {
    }
};

extern const struct socket_ops icmp6_ops;

class icmp6_socket : public inet_socket
{
private:
    static constexpr unsigned int icmp_max_filters = 5;
    spinlock filters_lock{};
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
    icmp6_socket()
    {
        spinlock_init(&filters_lock);
        sock_ops = &icmp6_ops;
    }

    ~icmp6_socket() override = default;

    int bind(struct sockaddr *addr, socklen_t addrlen);
    int connect(struct sockaddr *addr, socklen_t addrlen, int flags);
    ssize_t sendmsg(const struct kernel_msghdr *msg, int flags);
    int getsockopt(int level, int optname, void *val, socklen_t *len);
    int setsockopt(int level, int optname, const void *val, socklen_t len);
    short poll(void *poll_file, short events);
    ssize_t recvmsg(kernel_msghdr *msg, int flags);

    bool match_filter(const icmpv6_header *header)
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

icmp6_socket *create_socket(int type);

static constexpr unsigned int min_icmp6_size()
{
    return sizeof(icmpv6_header);
}

int handle_packet(netif *nif, packetbuf *buf);

int send_packet(const send_data &data, cul::slice<unsigned char> packet_data);

} // namespace icmpv6

#endif
