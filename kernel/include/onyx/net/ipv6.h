/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_NET_IPV6_H
#define _ONYX_NET_IPV6_H

#include <netinet/in.h>

#include <onyx/net/inet_proto_family.h>
#include <onyx/net/inet_route.h>
#include <onyx/net/inet_sock_addr.h>
#include <onyx/net/inet_socket.h>
#include <onyx/public/socket.h>

#include <onyx/tuple.hpp>

struct ip6hdr
{

#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int traffic_class : 4;
    unsigned int version : 4;
#else
    unsigned int version : 4;
    unsigned int traffic_class : 4;
#endif

    uint8_t flow_label[3];
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    in6_addr src_addr;
    in6_addr dst_addr;
} __attribute__((packed));

#define IN6ADDR_ALL_ROUTERS                                  \
    {                                                        \
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 \
    }
#define IN6ADDR_ALL_NODES                                    \
    {                                                        \
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 \
    }

#define IPV6_EXT_HEADER_HOP_BY_HOP 0

struct ipv6_option
{
    uint8_t type;
    uint8_t len;
};

struct ipv6_router_alert
{
    ipv6_option opt;
    uint16_t value;
};

#define IPV6_ROUTER_ALERT_MLD   0
#define IPV6_ROUTER_ALERT_RSVP  1
#define IPV6_ROUTER_ALERT_ACTVN 2

namespace ip::v6
{

/* IPv4-mapped IPv6 addresses are special addresses recognised by a
 * lot of hybrid dual-stack IPv4/v6 implementations. These addresses consist in an 80-bit prefix
 * of zeros, followed by 16 bits of ones and the remaining part of the address(32-bits) is the
 * IPv4 address.
 */
constexpr bool is_ipv4_mapped_addr(const sockaddr_in6 *sa)
{
    /* First we test the first 64-bits(two 32-bit compares), then we test the 5th 16-bit word,
     * such that we test for the 80-bits of zeros. Then we just test if the following 16-bit word
     * is 0xffff.
     */
    return sa->sin6_addr.s6_addr32[0] == 0 && sa->sin6_addr.s6_addr32[1] == 0 &&
           sa->sin6_addr.s6_addr16[4] == 0 && sa->sin6_addr.s6_addr16[5] == 0xffff;
}

constexpr in6_addr ipv4_to_ipv4_mapped(in_addr_t addr)
{
    in6_addr a;
    a.s6_addr32[0] = 0;
    a.s6_addr32[1] = 0;
    a.s6_addr16[4] = 0;
    a.s6_addr16[5] = 0xffff;
    a.s6_addr32[3] = addr;

    return a;
}

/* Used on IPv4-mapped IPv6 addresses */
constexpr in_addr sa6_to_ipv4(const sockaddr_in6 *sa)
{
    return {sa->sin6_addr.s6_addr32[3]};
}

inline constexpr cul::pair<inet_sock_address, int> sockaddr6_to_isa(const sockaddr_in6 *sa)
{
    if (is_ipv4_mapped_addr(sa))
        return {inet_sock_address{sa6_to_ipv4(sa), sa->sin6_port}, AF_INET};
    else
        return {inet_sock_address{*sa}, AF_INET6};
}

int send_packet(const iflow &flow, packetbuf *buf);

int handle_packet(netif *nif, packetbuf *buf);

socket *create_socket(int type, int protocol);

bool add_route(inet6_route &route);

int netif_addrcfg(netif *nif, const in6_addr &if_id);

class proto_family : public inet_proto_family
{
private:
    int bind_internal(sockaddr_in6 *in, inet_socket *sock);

public:
    int bind(sockaddr *addr, socklen_t len, inet_socket *socket) override;
    int bind_any(inet_socket *sock) override;
    expected<inet_route, int> route(const inet_sock_address &from, const inet_sock_address &to,
                                    int domain) override;
    void unbind(inet_socket *sock) override;
};

proto_family *get_v6_proto();
} // namespace ip::v6

#endif
