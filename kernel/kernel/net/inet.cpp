/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <onyx/net/icmp.h>
#include <onyx/net/icmpv6.h>
#include <onyx/net/ip.h>
#include <onyx/net/netif.h>
#include <onyx/net/socket_table.h>
#include <onyx/net/tcp.h>
#include <onyx/net/udp.h>
#include <onyx/public/socket.h>
#include <onyx/random.h>

namespace ip
{

socket *choose_protocol_and_create(int type, int protocol)
{
    switch (type)
    {
    case SOCK_DGRAM: {
        switch (protocol)
        {
        case IPPROTO_UDP:
            return udp_create_socket(type);
        case IPPROTO_ICMP:
            return icmp::create_socket(type);
        case IPPROTO_ICMPV6:
            return icmpv6::create_socket(type);
        default:
            return nullptr;
        }
    }

    case SOCK_STREAM: {
    case IPPROTO_TCP:
        return tcp_create_socket(type);
    default:
        return nullptr;
    }
    }
}

/* Use linux's ephemeral ports */
static constexpr in_port_t ephemeral_upper_bound = 61000;
static constexpr in_port_t ephemeral_lower_bound = 32768;

in_port_t allocate_ephemeral_port(inet_sock_address &addr, inet_socket *sock, int domain)
{
    auto sock_table = sock->proto_info->get_socket_table();

    while (true)
    {
        in_port_t port = htons(static_cast<in_port_t>(arc4random_uniform(ephemeral_upper_bound -
                                                                         ephemeral_lower_bound)) +
                               ephemeral_lower_bound);

        addr.port = port;

        /* We pass the same address as the dst address but in reality, dst_addr isn't checked. */
        const socket_id id{sock->proto, domain, addr, addr};

        const auto hash = inet_socket::make_hash_from_id(id);

        sock_table->lock(hash);

        auto sock = sock_table->get_socket(id, GET_SOCKET_CHECK_EXISTENCE | GET_SOCKET_UNLOCKED);

        if (!sock)
            return port;
        else
        {
            /* Let's try again, boys */
            sock_table->unlock(hash);
        }
    }
}

void copy_msgname_to_user(struct msghdr *msg, packetbuf *buf, bool isv6, in_port_t port)
{
    if (buf->domain == AF_INET && !isv6)
    {
        const ip_header *hdr = (const ip_header *) buf->net_header;
        sockaddr_in in;
        explicit_bzero(&in, sizeof(in));

        in.sin_family = AF_INET;
        in.sin_port = port;
        in.sin_addr.s_addr = hdr->source_ip;

        memcpy(msg->msg_name, &in, min(sizeof(in), (size_t) msg->msg_namelen));

        msg->msg_namelen = min(sizeof(in), (size_t) msg->msg_namelen);
    }
    else if (buf->domain == AF_INET && isv6)
    {
        const ip_header *hdr = (const ip_header *) buf->net_header;
        /* Create a v4-mapped v6 address */
        sockaddr_in6 in6;
        explicit_bzero(&in6, sizeof(in6));

        in6.sin6_family = AF_INET6;
        in6.sin6_flowinfo = 0;
        in6.sin6_port = port;
        in6.sin6_scope_id = 0;
        in6.sin6_addr = ip::v6::ipv4_to_ipv4_mapped(hdr->source_ip);

        memcpy(msg->msg_name, &in6, min(sizeof(in6), (size_t) msg->msg_namelen));

        msg->msg_namelen = min(sizeof(in6), (size_t) msg->msg_namelen);
    }
    else // if(buf->domain == AF_INET6)
    {
        const ip6hdr *hdr = (const ip6hdr *) buf->net_header;

        sockaddr_in6 in6;
        explicit_bzero(&in6, sizeof(in6));

        in6.sin6_family = AF_INET6;
        /* TODO: Probably not correct */
        in6.sin6_flowinfo = hdr->flow_label[0] | hdr->flow_label[1] << 8 | hdr->flow_label[2] << 16;
        ;
        in6.sin6_port = port;
        memcpy(&in6.sin6_addr, &hdr->src_addr, sizeof(hdr->src_addr));

        memcpy(msg->msg_name, &in6, msg->msg_namelen);

        msg->msg_namelen = min(sizeof(in6), (size_t) msg->msg_namelen);
    }
}

} // namespace ip

/**
 * @brief Copy an internal inet_sock_address to a generic sockaddr
 *
 * @param addr Const reference to an ISA
 * @param dst_addr Pointer to a destination sockaddr (should be sockaddr_storage wide)
 * @param len Pointer to wher eto put the length
 */
void inet_socket::copy_addr_to_sockaddr(const inet_sock_address &addr, sockaddr *dst_addr,
                                        socklen_t *len)
{
    auto domain = effective_domain();

    if (domain == AF_INET)
    {
        sockaddr_in addr;
        addr.sin_family = effective_domain();
        addr.sin_port = src_addr.port;
        memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

        // Note that memcpy is the only valid way to tell the compiler that we're not violating
        // any aliasing rules
        memcpy(dst_addr, &addr, sizeof(addr));
        *len = sizeof(addr);
    }
    else if (domain == AF_INET6)
    {
        sockaddr_in6 addr;
        addr.sin6_family = effective_domain();
        addr.sin6_port = src_addr.port;
        addr.sin6_addr = src_addr.in6;
        addr.sin6_flowinfo = 0; // TODO: Why do we not keep flowinfo?
        addr.sin6_scope_id = src_addr.v6_scope_id;

        memcpy(dst_addr, &addr, sizeof(addr));
        *len = sizeof(addr);
    }
}
