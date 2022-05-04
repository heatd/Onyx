/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_NET_INET_SOCKET_H
#define _ONYX_NET_INET_SOCKET_H

#include <onyx/byteswap.h>
#include <onyx/net/inet_cork.h>
#include <onyx/net/inet_proto.h>
#include <onyx/net/inet_route.h>
#include <onyx/net/inet_sock_addr.h>
#include <onyx/net/socket.h>

// Pretty solid TTL default
#define INET_DEFAULT_TTL 64

class inet_proto_family;

/* Forward declaration of ip::v4/v6::proto_family for inet_socket friendship */
namespace ip
{

namespace v4
{
class proto_family;
}

namespace v6
{
class proto_family;
}

void copy_msgname_to_user(struct msghdr *msg, packetbuf *buf, bool isv6, in_port_t port);

}; // namespace ip

struct inet_socket : public socket
{
    inet_sock_address src_addr;
    list_head_cpp<inet_socket> bind_table_node;
    inet_sock_address dest_addr;

    inet_route route_cache;

    struct list_head rx_packet_list;
    struct spinlock rx_packet_list_lock;

    wait_queue rx_wq;
    const inet_proto *proto_info;

    unsigned int ipv4_on_inet6 : 1, ipv6_only : 1, route_cache_valid : 1;
    int ttl;

    inet_socket()
        : socket{}, src_addr{}, bind_table_node{this}, dest_addr{}, proto_info{},
          ipv4_on_inet6{}, ipv6_only{}, route_cache_valid{}, ttl{INET_DEFAULT_TTL}
    {
        INIT_LIST_HEAD(&rx_packet_list);
        spinlock_init(&rx_packet_list_lock);
        init_wait_queue_head(&rx_wq);
    }

    constexpr bool in_ipv4_mode() const
    {
        return domain == AF_INET || ipv4_on_inet6;
    }

    constexpr int effective_domain() const
    {
        if (in_ipv4_mode())
            return AF_INET;
        else
            return AF_INET6;
    }

    static in_port_t get_port(inet_socket *sock, const inet_sock_address &addr)
    {
        return addr.port;
    }

    static uint32_t make_hash(inet_socket *&sock)
    {
        auto hash = fnv_hash(&sock->proto, sizeof(int));
        hash = fnv_hash_cont(&sock->src_addr.port, sizeof(in_port_t), hash);
        // printk("sockHashing proto %d port %u - hash %x\n", sock->proto,
        // ntohs(sock->src_addr.port), hash);

        return hash;
    }

    static uint32_t make_hash_from_id(const socket_id &id)
    {
        auto hash = fnv_hash(&id.protocol, sizeof(id.protocol));
        hash = fnv_hash_cont(&id.src_addr.port, sizeof(in_port_t), hash);
        // printk("idHashing proto %d port %u - hash %x\n", id.protocol, ntohs(id.src_addr.port),
        // hash);

        return hash;
    }

    bool is_id(const socket_id &id, unsigned int flags) const
    {
        const auto &this_src = src_addr;
        const auto &other_src = id.src_addr;

        if (ipv6_only && id.domain == AF_INET)
            return false;

        if (proto != id.protocol)
            return false;

        if (!this_src.is_any(in_ipv4_mode()) && !this_src.equals(other_src, in_ipv4_mode()))
            return false;

        if (flags & GET_SOCKET_DSTADDR_VALID && !dest_addr.equals(id.dst_addr, in_ipv4_mode()))
            return false;

        return true;
    }

    inet_proto_family *get_proto_fam()
    {
        return reinterpret_cast<inet_proto_family *>(proto_domain);
    }

    void append_inet_rx_pbuf(packetbuf *buf);

    virtual ~inet_socket();

    int setsockopt_inet(int level, int opt, const void *optval, socklen_t len);
    int getsockopt_inet(int level, int opt, void *optval, socklen_t *len);

    int setsockopt_inet4(int level, int opt, const void *optval, socklen_t len);
    int getsockopt_inet4(int level, int opt, void *optval, socklen_t *len);

    int setsockopt_inet6(int level, int opt, const void *optval, socklen_t len);
    int getsockopt_inet6(int level, int opt, void *optval, socklen_t *len);

    bool is_inet_level(int level) const
    {
        if (domain == AF_INET)
            return level == SOL_IP;
        else /* if(domain == AF_INET6) is implicit */
            return level == SOL_IPV6;
    }

    size_t get_headers_len() const;

    bool needs_fragmenting(netif *nif, packetbuf *buf) const;

    /**
     * @brief Check if we can offload the checksumming
     *        Usually, this should be possible if there's no fragmenting needed and the interface
     *        supports such a thing.
     * @param nif Network interface
     * @param buf Packet that we're trying to send
     * @return True if possible, else false
     */
    bool can_offload_csum(netif *nif, packetbuf *buf) const;

#define call_based_on_inet(func, ...) \
    ((effective_domain() == AF_INET6) ? func<AF_INET6>(__VA_ARGS__) : func<AF_INET>(__VA_ARGS__))

private:
    friend class ip::v4::proto_family;
    friend class ip::v6::proto_family;
    bool validate_sockaddr_len_pair_v4(sockaddr_in *addr, socklen_t len);
    bool validate_sockaddr_len_pair_v6(sockaddr_in6 *addr, socklen_t len);

protected:
    /* Modifies *addr too */
    bool validate_sockaddr_len_pair(sockaddr *addr, socklen_t len);
    void unbind();

    /**
     * @brief Copy an internal inet_sock_address to a generic sockaddr
     *
     * @param addr Const reference to an ISA
     * @param dst_addr Pointer to a destination sockaddr (should be sockaddr_storage wide)
     * @param len Pointer to wher eto put the length
     */
    void copy_addr_to_sockaddr(const inet_sock_address &addr, sockaddr *dst_addr, socklen_t *len);
};

#endif
