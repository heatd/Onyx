/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/byteswap.h>
#include <onyx/compiler.h>
#include <onyx/dev.h>
#include <onyx/net/icmp.h>
#include <onyx/net/inet_proto.h>
#include <onyx/net/ip.h>
#include <onyx/net/netif.h>
#include <onyx/net/socket_table.h>
#include <onyx/net/udp.h>
#include <onyx/packetbuf.h>
#include <onyx/poll.h>
#include <onyx/scoped_lock.h>
#include <onyx/utils.h>

#include <uapi/netinet.h>

#include <onyx/expected.hpp>
#include <onyx/memory.hpp>

socket_table udp_socket_table;

const inet_proto udp_proto{"udp", &udp_socket_table};

uint16_t udpv4_calculate_checksum(struct udphdr *header, uint32_t srcip, uint32_t dstip,
                                  bool do_rest_of_packet = true)
{
    uint16_t proto = IPPROTO_UDP << 8;
    uint16_t packet_length = ntohs(header->len);
    uint16_t __src[2];
    uint16_t __dst[2];

    memcpy(&__src, &srcip, sizeof(srcip));
    memcpy(&__dst, &dstip, sizeof(dstip));

    auto r = __ipsum_unfolded(&__src, sizeof(srcip), 0);
    r = __ipsum_unfolded(&__dst, sizeof(dstip), r);
    r = __ipsum_unfolded(&proto, sizeof(proto), r);
    r = __ipsum_unfolded(&header->len, sizeof(header->len), r);
    assert(header->checksum == 0);

    if (do_rest_of_packet)
        r = __ipsum_unfolded(header, packet_length, r);

    return ipsum_fold(r);
}

static void print_v6_addr(const in6_addr &addr)
{
    printk("%x:%x:%x:%x:%x:%x:%x:%x\n", ntohs(addr.s6_addr16[0]), ntohs(addr.s6_addr16[1]),
           ntohs(addr.s6_addr16[2]), ntohs(addr.s6_addr16[3]), ntohs(addr.s6_addr16[4]),
           ntohs(addr.s6_addr16[5]), ntohs(addr.s6_addr16[6]), ntohs(addr.s6_addr16[7]));
}

struct pseudo_csum
{
    in6_addr src;
    in6_addr dst;
    uint32_t length;
    uint8_t unused[3];
    uint8_t proto;
};

uint16_t udpv6_calculate_checksum(struct udphdr *header, const in6_addr &src, const in6_addr &dst,
                                  bool do_rest_of_packet = true)
{
    uint32_t proto = htonl(IPPROTO_UDP);
    uint32_t packet_length = htonl(ntohs(header->len));

    auto r = __ipsum_unfolded(&src, sizeof(src), 0);
    r = __ipsum_unfolded(&dst, sizeof(dst), r);
    r = __ipsum_unfolded(&packet_length, sizeof(packet_length), r);
    r = __ipsum_unfolded(&proto, sizeof(proto), r);
    assert(header->checksum == 0);

    if (do_rest_of_packet)
        r = __ipsum_unfolded(header, ntohl(packet_length), r);

    return ipsum_fold(r);
}

template <int domain>
uint16_t udp_calculate_checksum(struct udphdr *header, const inet_route::addr &src,
                                const inet_route::addr &dest, bool do_rest_of_packet = true)
{
    if constexpr (domain == AF_INET6)
    {
        return udpv6_calculate_checksum(header, src.in6, dest.in6, do_rest_of_packet);
    }
    else
    {
        return udpv4_calculate_checksum(header, src.in4.s_addr, dest.in4.s_addr, do_rest_of_packet);
    }
}

expected<ref_guard<packetbuf>, int> udp_create_pbuf(size_t payload_size, size_t headers_len)
{
    auto b = make_refc<packetbuf>();
    if (!b)
        return unexpected{-ENOMEM};

    if (!b->allocate_space(payload_size + headers_len + sizeof(udphdr) + PACKET_MAX_HEAD_LENGTH))
        return unexpected{-ENOMEM};

    b->reserve_headers(headers_len + sizeof(udphdr) + PACKET_MAX_HEAD_LENGTH);

    return b;
}

int udp_socket::bind(sockaddr *addr, socklen_t len)
{
    auto fam = get_proto_fam();
    return fam->bind(addr, len, this);
}

int udp_socket::connect(sockaddr *addr, socklen_t len, int flags)
{
    if (!validate_sockaddr_len_pair(addr, len))
        return -EINVAL;

    auto res = sockaddr_to_isa(addr);
    dest_addr = res.first;

    bool on_ipv4_mode = res.second == AF_INET && domain == AF_INET6;

    // printk("udp: Connected to address %x\n", dest_addr.in4.s_addr);

    if (!bound)
    {
        /* TODO: Dunno if this can work */
        auto fam = get_proto_fam();
        int st = fam->bind_any(this);
        if (st < 0)
            return st;
    }

    ipv4_on_inet6 = on_ipv4_mode;

    auto route_result = get_proto_fam()->route(src_addr, dest_addr, res.second);

    if (route_result.has_error())
    {
        return route_result.error();
    }

    route_cache = route_result.value();

    if (route_cache.flags & (INET4_ROUTE_FLAG_BROADCAST | INET4_ROUTE_FLAG_MULTICAST) &&
        !broadcast_allowed)
    {
        return -EACCES;
    }

    route_cache_valid = 1;

    connected = true;

    return 0;
}

void udp_prepare_headers(packetbuf *buf, in_port_t sport, in_port_t dport, size_t len)
{
    auto udp_header = (udphdr *) buf->push_header(sizeof(udphdr));

    buf->transport_header = (unsigned char *) udp_header;

    udp_header->source_port = sport;
    udp_header->dest_port = dport;
    udp_header->len = htons((uint16_t) (sizeof(udphdr) + len));
    udp_header->checksum = 0;
}

int udp_put_data(packetbuf *buf, const msghdr *msg, size_t length)
{
    unsigned char *ptr = (unsigned char *) buf->put((unsigned int) length);

    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        const auto &vec = msg->msg_iov[i];
        if (copy_from_user(ptr, vec.iov_base, vec.iov_len) < 0)
            return -EFAULT;

        ptr += vec.iov_len;
    }

    return 0;
}

template <int domain>
void udp_do_csum(packetbuf *buf, const inet_route &route)
{
    auto hdr = (udphdr *) buf->transport_header;
    auto netif = route.nif;

    /* TODO: Take options into account */
    auto ip_hdr_size = inet_header_size(domain);

    if (netif->flags & NETIF_SUPPORTS_CSUM_OFFLOAD && netif->mtu >= buf->length() + ip_hdr_size)
    {
        /* Don't supply the 1's complement of the checksum, since the network stack expects a
         * partial sum */
        hdr->checksum = ~udp_calculate_checksum<domain>(hdr, route.src_addr, route.dst_addr, false);
        buf->csum_offset = &hdr->checksum;
        buf->csum_start = (unsigned char *) hdr;
        buf->needs_csum = 1;
    }
    else
        hdr->checksum = udp_calculate_checksum<domain>(hdr, route.src_addr, route.dst_addr);

    // printk("Checksum: %x\n", hdr->checksum);
}

template <int domain>
int udp_do_send(packetbuf *buf, const inet_route &route)
{
    int ret;

    iflow flow{route, IPPROTO_UDP, domain == AF_INET6};

    if constexpr (domain == AF_INET6)
        ret = ip::v6::send_packet(flow, buf);
    else
        ret = ip::v4::send_packet(flow, buf);

    return ret;
}

template <typename AddrType>
ssize_t udp_socket::udp_sendmsg(const msghdr *msg, int flags, const inet_sock_address &dst)
{
    bool wanting_cork = wants_cork || flags & MSG_MORE;
    bool will_append = false;

    auto payload_size = iovec_count_length(msg->msg_iov, msg->msg_iovlen);
    if (payload_size < 0)
        return payload_size;

    if (payload_size > UINT16_MAX)
        return -EMSGSIZE;

    inet_route route;

    constexpr auto our_domain = inet_domain_type_v<AddrType>;

    will_append = wanting_cork;

    auto &cork_pending = cork.pending();

    if (cork_pending)
    {
        scoped_hybrid_lock g{socket_lock, this};

        if (cork_pending)
        {
            /* Our cork needs everything to be of the same domain, else things might
             * blow up a bit spectacularly.
             */
            if (cork_pending != our_domain)
            {
                return -EINVAL;
            }

            /* If we reached here, we know we're corking, so we set will_append to true
             * so the following code knows this.
             */
            will_append = true;
        }
    }

    static_assert(our_domain == AF_INET || our_domain == AF_INET6,
                  "UDP only supports INET or INET6");

    if (connected && route_cache_valid)
    {
        route = route_cache;
    }
    else
    {
        auto fam = get_proto_fam();
        auto result = fam->route(src_addr, dst, our_domain);
        if (result.has_error())
        {
            // printk("died with error %d\n", result.error());
            return result.error();
        }

        route = result.value();
    }

    /* If we're not corking, do the fast path. This path doesn't require locks since it's a simple
     * datagram.
     */
    if (!will_append) [[likely]]
    {
        auto pbf_st = udp_create_pbuf(payload_size, inet_header_size(our_domain));

        if (pbf_st.has_error())
            return pbf_st.error();

        auto buf = pbf_st.value();

        udp_prepare_headers(buf.get(), src_addr.port, dst.port, payload_size);

        if (udp_put_data(buf.get(), msg, payload_size) < 0)
            return -EFAULT;

        udp_do_csum<our_domain>(buf.get(), route);

        if (int st = udp_do_send<our_domain>(buf.get(), route); st < 0)
            return st;

        return payload_size;
    }

    scoped_hybrid_lock g{socket_lock, this};

    cork_pending = our_domain;

    /* Woohoo, corking path! */
    if (int st = cork.append_data(msg->msg_iov, msg->msg_iovlen, sizeof(udphdr), 0xffff); st < 0)
    {
        return st;
    }

#if DEBUG_UDP_CORK
    printk("appending %lu, total len %u\n", msg->msg_iov[0].iov_len,
           list_head_cpp<packetbuf>::self_from_list_head(list_first_element(cork.get_packet_list()))
               ->length());
#endif

    if (!wanting_cork)
    {
        iflow fl{route, src_addr, dst, IPPROTO_UDP};
        int st = cork.send(fl, [](packetbuf *buf, const iflow &flow) {
            udp_prepare_headers(buf, flow.saddr.port, flow.daddr.port, buf->length());

            udp_do_csum<our_domain>(buf, flow.route);
        });

        return st < 0 ? st : payload_size;
    }

    return payload_size;
}

ssize_t udp_socket::sendmsg(const msghdr *msg, int flags)
{
    sockaddr *addr = (sockaddr *) msg->msg_name;
    if (addr && !validate_sockaddr_len_pair(addr, msg->msg_namelen))
        return -EINVAL;

    if (!connected && addr == nullptr)
        return -EDESTADDRREQ;

    inet_sock_address dest = dest_addr;
    int our_domain = effective_domain();

    if (addr)
    {
        auto res = sockaddr_to_isa(addr);
        dest = res.first;
        our_domain = res.second;
    }

    if (our_domain == AF_INET)
        return udp_sendmsg<in_addr>(msg, flags, dest);
    else
        return udp_sendmsg<in6_addr>(msg, flags, dest);
}

socket *udp_create_socket(int type)
{
    auto sock = new udp_socket;

    if (sock)
    {
        sock->proto_info = &udp_proto;
    }

    return sock;
}

int udp_init_netif(netif *netif)
{
    return 0;
}

bool valid_udp_packet(struct udphdr *header, size_t length)
{
    if (sizeof(struct udphdr) > length)
        return false;
    if (ntohs(header->len) > length)
        return false;

    return true;
}

/**
 * @brief Handle receive of a multicast/broadcast packet
 *
 * @param route Inet route
 * @param buf Packetbuf
 * @return 0 on success, negative error codes
 */
int udp_handle_packet_mcast_bcast(const inet_route &route, packetbuf *buf)
{
    struct udphdr *udp_header = (struct udphdr *) buf->data;

    auto header = (ip_header *) buf->net_header;
    buf->transport_header = (unsigned char *) udp_header;
    buf->data += sizeof(struct udphdr);

    sockaddr_in socket_dst;
    ipv4_to_sockaddr(header->source_ip, udp_header->source_port, socket_dst);

    unsigned int instance = 0;
    while (true)
    {
        auto socket = inet_resolve_socket<udp_socket>(header->source_ip, udp_header->source_port,
                                                      udp_header->dest_port, IPPROTO_UDP, route.nif,
                                                      true, &udp_proto, instance++);
        if (!socket)
            break;

        // Only SO_BROADCAST sockets can get broadcast packets
        if (route.flags & INET4_ROUTE_FLAG_BROADCAST && !socket->broadcast_allowed) [[unlikely]]
            continue;

        // I don't think we need to copy here?
        socket->rx_dgram(buf);
        socket->unref();
    }

    return 0;
}

void udp_socket::rx_dgram(packetbuf *buf)
{
    scoped_hybrid_lock<true> g{socket_lock, this};

    if (!socket_lock.is_ours())
    {
        buf->ref();
        add_backlog(&buf->list_node);
        return;
    }

    append_inet_rx_pbuf(buf);
}

/**
 * @brief Handle UDP socket backlog
 *
 */
void udp_socket::handle_backlog()
{
    // Take every packet and queue it
    list_for_every_safe (&socket_backlog)
    {
        auto pbuf = list_head_cpp<packetbuf>::self_from_list_head(l);
        list_remove(&pbuf->list_node);
        append_inet_rx_pbuf(pbuf);
        pbuf->unref();
    }
}

int udp_handle_packet(const inet_route &route, packetbuf *buf)
{
    struct udphdr *udp_header = (struct udphdr *) buf->data;

    if (!valid_udp_packet(udp_header, buf->length()))
        return -EINVAL;

    auto header = (ip_header *) buf->net_header;

    sockaddr_in socket_dst;
    ipv4_to_sockaddr(header->source_ip, udp_header->source_port, socket_dst);

    if (route.flags & (INET4_ROUTE_FLAG_BROADCAST | INET4_ROUTE_FLAG_MULTICAST))
    {
        return udp_handle_packet_mcast_bcast(route, buf);
    }

    auto socket = inet_resolve_socket<udp_socket>(header->source_ip, udp_header->source_port,
                                                  udp_header->dest_port, IPPROTO_UDP, route.nif,
                                                  true, &udp_proto);
    if (!socket)
    {
        // Note: We only send ICMP messages for unicast addresses
        icmp::dst_unreachable_info dst_un{ICMP_CODE_PORT_UNREACHABLE, 0,
                                          (const unsigned char *) udp_header, header};
        icmp::send_dst_unreachable(dst_un, route.nif);
        return 0;
    }

    buf->transport_header = (unsigned char *) udp_header;
    buf->data += sizeof(struct udphdr);

    socket->rx_dgram(buf);

    socket->unref();
    return 0;
}

int udp_handle_packet_v6(netif *netif, packetbuf *buf)
{
    struct udphdr *udp_header = (struct udphdr *) buf->data;

    if (!valid_udp_packet(udp_header, buf->length()))
        return -EINVAL;

    auto header = (ip6hdr *) buf->net_header;

    auto socket = inet6_resolve_socket<udp_socket>(header->src_addr, udp_header->source_port,
                                                   header->dst_addr, udp_header->dest_port,
                                                   IPPROTO_UDP, netif, true, &udp_proto);
    if (!socket)
    {
        /* TODO: Implement ICMPV6 dst unreachables, etc */
#if 0
		icmp::dst_unreachable_info dst_un{ICMP_CODE_PORT_UNREACHABLE, 0,
		                (const unsigned char *) udp_header, header};
		icmp::send_dst_unreachable(dst_un, netif);
#endif
        return 0;
    }

    buf->transport_header = (unsigned char *) udp_header;
    buf->data += sizeof(struct udphdr);

    socket->rx_dgram(buf);

    socket->unref();
    return 0;
}

expected<packetbuf *, int> udp_socket::get_datagram(int flags)
{
    int st = 0;
    packetbuf *buf = nullptr;

    do
    {
        if (st == -EINTR)
            return unexpected<int>{st};

        buf = get_rx_head();
        if (!buf && flags & MSG_DONTWAIT)
            return unexpected<int>{-EWOULDBLOCK};

        st = wait_for_dgrams();
    } while (!buf);

    return buf;
}

ssize_t udp_socket::recvmsg(msghdr *msg, int flags)
{
    auto iovlen = iovec_count_length(msg->msg_iov, msg->msg_iovlen);
    if (iovlen < 0)
        return iovlen;

    scoped_hybrid_lock hlock{socket_lock, this};

    auto st = get_datagram(flags);
    if (st.has_error())
        return st.error();

    auto buf = st.value();
    ssize_t read = min(iovlen, (long) buf->length());
    ssize_t was_read = 0;
    ssize_t to_ret = read;

    if (iovlen < buf->length())
        msg->msg_flags = MSG_TRUNC;

    if (flags & MSG_TRUNC)
    {
        to_ret = buf->length();
    }

    const unsigned char *ptr = buf->data;

    if (msg->msg_name)
    {
        auto hdr = (udphdr *) buf->transport_header;
        ip::copy_msgname_to_user(msg, buf, domain == AF_INET6, hdr->source_port);
    }

    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        auto iov = msg->msg_iov[i];
        auto to_copy = min((ssize_t) iov.iov_len, read - was_read);
        if (copy_to_user(iov.iov_base, ptr, to_copy) < 0)
        {
            return -EFAULT;
        }

        was_read += to_copy;

        ptr += to_copy;
    }

    msg->msg_controllen = 0;

    if (!(flags & MSG_PEEK))
    {
        list_remove(&buf->list_node);
        buf->unref();
    }

#if 0
	printk("recv success %ld bytes\n", read);
	printk("iovlen %ld\n", iovlen);
#endif

    return to_ret;
}

int udp_socket::getsockopt(int level, int optname, void *val, socklen_t *len)
{
    if (is_inet_level(level))
        return getsockopt_inet(level, optname, val, len);
    if (level == SOL_SOCKET)
        return getsockopt_socket_level(optname, val, len);

    if (level == SOL_UDP)
    {
        switch (optname)
        {
            case UDP_CORK: {
                return put_option(truthy_to_int(wants_cork), val, len);
            }
        }
    }

    return -ENOPROTOOPT;
}

int udp_socket::setsockopt(int level, int optname, const void *val, socklen_t len)
{
    if (is_inet_level(level))
        return setsockopt_inet(level, optname, val, len);
    if (level == SOL_SOCKET)
        return setsockopt_socket_level(optname, val, len);

    if (level == SOL_UDP)
    {
        switch (optname)
        {
            case UDP_CORK: {
                auto res = get_socket_option<int>(val, len);
                if (res.has_error())
                    return res.error();

                wants_cork = int_to_truthy(res.value());
                return 0;
            }
        }
    }

    return -ENOPROTOOPT;
}

short udp_socket::poll(void *poll_file, short events)
{
    short avail_events = POLLOUT;

    scoped_hybrid_lock hlock{socket_lock, this};

    if (events & POLLIN)
    {
        if (has_data_available())
            avail_events |= POLLIN;
        else
            poll_wait_helper(poll_file, &rx_wq);
    }

    // printk("avail events: %u\n", avail_events);

    return avail_events & events;
}

int udp_socket::getsockname(sockaddr *addr, socklen_t *len)
{
    copy_addr_to_sockaddr(src_addr, addr, len);

    return 0;
}

int udp_socket::getpeername(sockaddr *addr, socklen_t *len)
{
    copy_addr_to_sockaddr(dest_addr, addr, len);
    return 0;
}
