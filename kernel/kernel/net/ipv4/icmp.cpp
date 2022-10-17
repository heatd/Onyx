/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/byteswap.h>
#include <onyx/cred.h>
#include <onyx/net/icmp.h>
#include <onyx/net/inet_proto.h>
#include <onyx/net/ip.h>
#include <onyx/net/network.h>
#include <onyx/net/socket_table.h>
#include <onyx/packetbuf.h>
#include <onyx/poll.h>
#include <onyx/public/icmp.h>
#include <onyx/vfs.h>

#include <onyx/memory.hpp>

/* TODO: Maybe a table isn't the best idea and we could just have a list here?
 * Since this is just a list (because all ports are 0), we're just wasting a bunch of memory
 * in all the other buckets' locks and list_head's.
 */
socket_table icmp_table;
const inet_proto icmp_proto{"icmp", &icmp_table};

#define ICMP_PACKETBUF_HEADER_SPACE \
    (PACKET_MAX_HEAD_LENGTH + sizeof(ip_header) + sizeof(icmp::icmp_header))

namespace icmp
{

ref_guard<packetbuf> allocate_icmp_response_packet(unsigned int extra_size = 0)
{
    auto buf = make_refc<packetbuf>();
    if (!buf)
        return {};

    if (!buf->allocate_space(ICMP_PACKETBUF_HEADER_SPACE + extra_size))
        return {};

    buf->reserve_headers(ICMP_PACKETBUF_HEADER_SPACE);

    return buf;
}

void send_echo_reply(ip_header *iphdr, icmp_header *icmphdr, uint16_t length, netif *nif)
{
    in_addr dst;
    dst.s_addr = iphdr->source_ip;
    auto src = nif->local_ip.sin_addr;

    auto data_length = length - min_icmp_size();

    auto buf = allocate_icmp_response_packet(data_length);
    if (!buf)
        return;

    auto response_icmp = (icmp_header *) buf->push_header(min_icmp_size());

    response_icmp->type = ICMP_TYPE_ECHO_REPLY;
    response_icmp->code = 0;
    response_icmp->rest = icmphdr->rest;
    memcpy(buf->put(data_length), &icmphdr->echo.data, data_length);
    response_icmp->checksum = ipsum(response_icmp, length);

    inet_sock_address from{src, 0};
    inet_sock_address to{dst, 0};

    auto res = ip::v4::get_v4_proto()->route(from, to, AF_INET);

    if (res.has_error())
        return;

    iflow flow{res.value(), IPPROTO_ICMP, false};

    ip::v4::send_packet(flow, buf.get());
}

int send_dst_unreachable(const dst_unreachable_info &info, netif *nif)
{
    in_addr dst;
    dst.s_addr = info.iphdr->source_ip;
    auto src = nif->local_ip.sin_addr;

    auto buf = allocate_icmp_response_packet();
    if (!buf)
        return -ENOMEM;

    auto response_icmp = (icmp_header *) buf->push_header(sizeof(icmp_header));

    response_icmp->type = ICMP_TYPE_DEST_UNREACHABLE;
    response_icmp->code = info.code;

    if (info.code == ICMP_CODE_FRAGMENTATION_REQUIRED)
        response_icmp->rest = htonl(info.next_hop_mtu << 16);
    else
        response_icmp->rest = 0;

    memcpy(&response_icmp->dest_unreach.header, info.iphdr, sizeof(ip_header));
    memcpy(&response_icmp->dest_unreach.original_dgram, info.dgram, 8);
    response_icmp->checksum = 0;
    response_icmp->checksum = ipsum(response_icmp, sizeof(icmp_header));

    inet_sock_address from{src, 0};
    inet_sock_address to{dst, 0};

    auto res = ip::v4::get_v4_proto()->route(from, to, AF_INET);

    if (res.has_error())
        return res.error();

    iflow flow{res.value(), IPPROTO_ICMP, false};

    return ip::v4::send_packet(flow, buf.get());
}

int handle_packet(const inet_route &route, packetbuf *buf)
{
    if (buf->length() < min_icmp_size())
        return -EINVAL;

    ip_header *iphdr = (ip_header *) buf->net_header;

    auto header = (icmp_header *) buf->data;
    auto header_length = buf->length();

    switch (header->type)
    {
        case ICMP_TYPE_ECHO_REQUEST:
            send_echo_reply(iphdr, header, header_length, route.nif);
            break;
    }

    icmp_socket *socket = nullptr;
    unsigned int inst = 0;

    do
    {
        socket = inet_resolve_socket<icmp_socket>(iphdr->source_ip, 0, 0, IPPROTO_ICMP, route.nif,
                                                  true, &icmp_proto, inst);
        if (!socket)
            break;
        inst++;

        if (socket->match_filter(header))
        {
            auto pbf = packetbuf_clone(buf);
            /* Out of memory, give up trying to clone this packet to other sockets */
            if (!pbf)
                break;

            socket->rx_dgram(pbf);
            pbf->unref();
        }

        socket->unref();

    } while (socket != nullptr);

    return 0;
}

int icmp_socket::bind(sockaddr *addr, socklen_t len)
{
    if (!validate_sockaddr_len_pair(addr, len))
        return -EINVAL;

    auto proto = get_proto_fam();
    return proto->bind(addr, len, this);
}

int icmp_socket::connect(sockaddr *addr, socklen_t len, int flags)
{
    if (!validate_sockaddr_len_pair(addr, len))
        return -EINVAL;

    auto res = sockaddr_to_isa(addr);
    dest_addr = res.first;

    bool on_ipv4_mode = res.second == AF_INET && domain == AF_INET6;

    // printk("udp: Connected to address %x\n", dest_addr.in4.s_addr);

    if (!bound)
    {
        auto fam = get_proto_fam();
        int st = fam->bind_any(this);
        if (st < 0)
            return st;
    }

    ipv4_on_inet6 = on_ipv4_mode;

    connected = true;

    auto route_result = get_proto_fam()->route(src_addr, dest_addr, res.second);

    /* If we've got an error, ignore it. Is this correct/sane behavior? */
    if (route_result.has_error())
    {
        connected = false;
        return 0;
    }

    route_cache = route_result.value();
    route_cache_valid = 1;

    return 0;
}

bool is_security_sensitive_icmp_packet(icmp_header *header)
{
    return header->type != ICMP_TYPE_ECHO_REQUEST;
}

ssize_t icmp_socket::sendmsg(const struct msghdr *msg, int flags)
{
    auto iovlen = iovec_count_length(msg->msg_iov, msg->msg_iovlen);
    if (iovlen < 0)
        return iovlen;

    if (iovlen < min_icmp_size())
        return -EINVAL;

    if (iovlen > UINT16_MAX)
        return -EINVAL;

    auto sa_dst_addr = (sockaddr *) msg->msg_name;

    auto to = dest_addr;

    if (msg->msg_name)
    {
        if (!validate_sockaddr_len_pair(sa_dst_addr, msg->msg_namelen))
            return -EINVAL;

        auto res = sockaddr_to_isa(sa_dst_addr);
        to = res.first;
    }
    else
    {
        if (!connected)
            return -ENOTCONN;
    }

    if (!bound)
    {
        auto fam = get_proto_fam();
        int st = fam->bind_any(this);
        if (st < 0)
            return st;
    }

    unsigned int extra_size = iovlen - min_icmp_size();

    auto packet = allocate_icmp_response_packet(extra_size);
    if (!packet)
        return -ENOBUFS;

    inet_route rt;

    if (connected && route_cache_valid)
    {
        rt = route_cache;
    }
    else
    {
        auto proto = get_proto_fam();
        auto st = proto->route(src_addr, to, AF_INET);
        if (st.has_error())
            return st.error();

        rt = st.value();
    }

    auto hdr = (icmp_header *) packet->push_header(min_icmp_size());
    packet->put(extra_size);
    auto p = (unsigned char *) hdr;

    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        auto &vec = msg->msg_iov[i];

        if (copy_from_user(p, vec.iov_base, vec.iov_len) < 0)
            return -EFAULT;

        p += vec.iov_len;
    }

    if (is_security_sensitive_icmp_packet(hdr) && !is_root_user())
        return -EPERM;

    hdr->checksum = 0;

    hdr->checksum = ipsum(hdr, iovlen);

    iflow flow{rt, IPPROTO_ICMP, false};

    return ip::v4::send_packet(flow, packet.get());
}

int icmp_socket::getsockopt(int level, int optname, void *val, socklen_t *len)
{
    if (is_inet_level(level))
        return getsockopt_inet(level, optname, val, len);
    if (level == SOL_SOCKET)
        return getsockopt_socket_level(optname, val, len);

    return -ENOPROTOOPT;
}

int icmp_socket::add_filter(icmp_filter &&f)
{
    scoped_lock g{filters_lock};

    bool is_root = is_root_user();

    if ((f.type == ICMP_FILTER_TYPE_UNSPEC || f.type != ICMP_TYPE_ECHO_REPLY) && !is_root)
    {
        return -EPERM;
    }

    if (filters.size() + 1 > icmp_max_filters && !is_root)
        return -EPERM;

    return filters.push_back(cul::move(f)) ? 0 : -ENOMEM;
}

int icmp_socket::setsockopt(int level, int optname, const void *val, socklen_t len)
{
    if (is_inet_level(level))
        return setsockopt_inet(level, optname, val, len);
    if (level == SOL_SOCKET)
        return setsockopt_socket_level(optname, val, len);

    if (level != SOL_ICMP)
        return -ENOPROTOOPT;

    switch (optname)
    {
        case ICMP_ADD_FILTER: {
            auto res = get_socket_option<icmp_filter>(val, len);
            if (res.has_error())
                return res.error();

            return add_filter(cul::move(res.value()));
        }
    }

    return -ENOPROTOOPT;
}

expected<packetbuf *, int> icmp_socket::get_datagram(int flags)
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

ssize_t icmp_socket::recvmsg(msghdr *msg, int flags)
{
    auto iovlen = iovec_count_length(msg->msg_iov, msg->msg_iovlen);
    if (iovlen < 0)
        return iovlen;

    scoped_hybrid_lock hlock{socket_lock, this};

    auto st = get_datagram(flags);
    if (st.has_error())
        return st.error();

    auto buf = st.value();
    ssize_t read = iovlen;

    if (iovlen < buf->length())
        msg->msg_flags = MSG_TRUNC;

    if (flags & MSG_TRUNC)
    {
        read = buf->length();
    }

    auto ptr = buf->data;

    if (msg->msg_name)
    {
        const ip_header *hdr = (const ip_header *) buf->net_header;
        sockaddr_in in;
        explicit_bzero(&in, sizeof(in));

        in.sin_family = AF_INET;
        in.sin_port = 0;
        in.sin_addr.s_addr = hdr->source_ip;

        memcpy(msg->msg_name, &in, min(sizeof(in), (size_t) msg->msg_namelen));

        msg->msg_namelen = min(sizeof(in), (size_t) msg->msg_namelen);
    }

    auto packet_length = buf->length();
    auto to_read = min(read, (ssize_t) packet_length);

    if (!(flags & MSG_TRUNC))
        read = to_read;

    for (int i = 0; to_read != 0; i++)
    {
        auto iov = msg->msg_iov[i];
        auto to_copy = min((ssize_t) iov.iov_len, to_read);

        if (copy_to_user(iov.iov_base, ptr, to_copy) < 0)
        {
            return -EFAULT;
        }

        ptr += to_copy;
        to_read -= to_copy;
    }

    msg->msg_controllen = 0;

    if (!(flags & MSG_PEEK))
    {
        list_remove(&buf->list_node);
        buf->unref();
    }

    return read;
}

short icmp_socket::poll(void *poll_file, short events)
{
    scoped_hybrid_lock hlock{socket_lock, this};
    short avail_events = POLLOUT;

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

icmp_socket *create_socket(int type)
{
    auto sock = new icmp_socket();

    if (sock)
    {
        sock->proto_info = &icmp_proto;
    }

    return sock;
}

void icmp_socket::rx_dgram(packetbuf *buf)
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
 * @brief Handle ICMP socket backlog
 *
 */
void icmp_socket::handle_backlog()
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

} // namespace icmp
