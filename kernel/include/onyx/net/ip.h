/*
 * Copyright (c) 2016-2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_NET_IP_H
#define _ONYX_NET_IP_H

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdint.h>

#include <onyx/net/inet_csum.h>
#include <onyx/net/inet_packet_flow.h>
#include <onyx/net/inet_proto.h>
#include <onyx/net/inet_proto_family.h>
#include <onyx/net/inet_route.h>
#include <onyx/net/inet_sock_addr.h>
#include <onyx/net/ipv6.h>
#include <onyx/net/netif.h>
#include <onyx/net/proto_family.h>
#include <onyx/net/socket.h>
#include <onyx/net/socket_table.h>
#include <onyx/packetbuf.h>
#include <onyx/public/socket.h>

struct ip_header
{
    /* These bitfields are screwing up the structure's size, although I think
     * it's an intellisense problem. The problem doesn't seem to arise when compiling the code.
     */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl : 4;
    unsigned int version : 4;
#else
    unsigned int version : 4;
    unsigned int ihl : 4;
#endif
    uint8_t tos;
    uint16_t total_len;
    uint16_t identification;
    uint16_t frag_info;
    uint8_t ttl;
    uint8_t proto;
    uint16_t header_checksum;
    uint32_t source_ip;
    uint32_t dest_ip;
} __attribute__((packed));

static constexpr uint16_t ip_header_length(const ip_header *hdr)
{
    return hdr->ihl << 2;
}

union sockaddr_in_both {
    sockaddr_in in4;
    sockaddr_in6 in6;
};

#define IPV4_MIN_HEADER_LEN 20

#define IPV4_FRAG_INFO_DONT_FRAGMENT  0x4000
#define IPV4_FRAG_INFO_MORE_FRAGMENTS 0x2000

#define IPV4_FRAG_INFO_FLAGS(x) (x & 0x7)
#define IPV4_MAKE_FRAGOFF(x)    (x << 3)
#define IPV4_GET_FRAGOFF(x)     (x >> 2)

namespace ip
{

namespace v4
{

class proto_family : public inet_proto_family
{
private:
    int bind_internal(sockaddr_in *in, inet_socket *sock);

public:
    int bind(sockaddr *addr, socklen_t len, inet_socket *socket) override;
    int bind_any(inet_socket *sock) override;
    expected<inet_route, int> route(const inet_sock_address &from, const inet_sock_address &to,
                                    int domain) override;
    void unbind(inet_socket *sock) override;
};

int send_packet(const iflow &flow, packetbuf *buf, cul::slice<ip_option> options = {});

socket *create_socket(int type, int protocol);

int handle_packet(netif *nif, packetbuf *buf);

bool add_route(inet4_route &route);

inline constexpr cul::pair<inet_sock_address, int> sockaddr4_to_isa(const sockaddr_in *sa)
{
    return {inet_sock_address{*sa}, AF_INET};
}

inet_proto_family *get_v4_proto();

}; // namespace v4

socket *choose_protocol_and_create(int type, int protocol);

/**
 * @brief Picks an ephemeral port through trial and error, using arc4random.
 *
 * @param addr The inet_sock_address where the port will be put
 * @param sock The socket to be bound
 * @param domain The socket's domain
 * @return in_port_t The ephemeral port
 */
in_port_t allocate_ephemeral_port(inet_sock_address &addr, inet_socket *sock, int domain);

}; // namespace ip

inline void ipv4_to_sockaddr(in_addr_t addr, in_port_t port, sockaddr_in &in)
{
    in.sin_addr.s_addr = addr;
    in.sin_family = AF_INET;
    in.sin_port = port;
    memset(&in.sin_zero, 0, sizeof(in.sin_zero));
}

inline void ipv6_to_sockaddr(const in6_addr &addr, in_port_t port, sockaddr_in6 &in)
{
    in.sin6_addr = addr;
    in.sin6_family = AF_INET6;
    in.sin6_port = port;
    in.sin6_scope_id = 0;
    in.sin6_flowinfo = 0;
}

inline bool check_sockaddr_in(sockaddr_in *in)
{
    if (in->sin_family != AF_INET)
        return false;

    memset(&in->sin_zero, 0, sizeof(in->sin_zero));
    return true;
}

/* This routine also handles broadcast addresses and all complexity envolved with ip addresses */
template <typename T>
inline T *inet_resolve_socket(in_addr_t src, in_port_t port_src, in_port_t port_dst, int proto,
                              netif *nif, bool ign_dst, const inet_proto *proto_info,
                              unsigned int instance = 0)
{
    in_addr __src;
    __src.s_addr = src;
    auto flags = (!ign_dst ? GET_SOCKET_DSTADDR_VALID : 0);

    const inet_sock_address socket_dst{__src, port_src};
    const inet_sock_address socket_src{nif->local_ip.sin_addr, port_dst};

    const socket_id id(proto, AF_INET, socket_src, socket_dst);

    auto socket = proto_info->get_socket_table()->get_socket(id, flags, instance);

    return static_cast<T *>(socket);
}

template <typename T>
inline T *inet6_resolve_socket(const in6_addr &src, in_port_t port_src, in_port_t port_dst,
                               int proto, netif *nif, bool ign_dst, const inet_proto *proto_info,
                               unsigned int instance = 0)
{
    const in6_addr &__src = src;
    auto flags = (!ign_dst ? GET_SOCKET_DSTADDR_VALID : 0);

    const inet_sock_address socket_dst{__src, port_src, nif->if_id};
    /* TODO: Fix this */
    const inet_sock_address socket_src{in6addr_any, port_dst, nif->if_id};

    const socket_id id(proto, AF_INET6, socket_src, socket_dst);

    auto socket = proto_info->get_socket_table()->get_socket(id, flags, instance);

    return static_cast<T *>(socket);
}

/* Ports under 1024 are privileged; they can only bound to by root. */
static constexpr uint16_t inet_min_unprivileged_port = 1024;

/* 'port' is a big-endian(or network order) variable */
bool inet_has_permission_for_port(in_port_t port);

/**
 * @brief Converts a plain, generic sockaddr into an internal representation, and handles IPv6
 * cleanly.
 *
 * @param sa the socket address
 * @return cul::pair<inet_sock_address, int> a pair representing the socket address and the domain
 */
inline cul::pair<inet_sock_address, int> sockaddr_to_isa(const sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return ip::v4::sockaddr4_to_isa(reinterpret_cast<const sockaddr_in *>(sa));
    else
        return ip::v6::sockaddr6_to_isa(reinterpret_cast<const sockaddr_in6 *>(sa));
}

constexpr size_t inet_header_size(int domain)
{
    /* Add some extra bytes for options, should be enough I think */
    size_t size = 100;
    if (domain == AF_INET)
        size += sizeof(ip_header);
    else
        size += sizeof(ip6hdr);

    return size;
}

#endif
