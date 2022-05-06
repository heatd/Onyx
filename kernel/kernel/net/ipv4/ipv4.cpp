/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/byteswap.h>
#include <onyx/cred.h>
#include <onyx/init.h>
#include <onyx/net/arp.h>
#include <onyx/net/ethernet.h>
#include <onyx/net/icmp.h>
#include <onyx/net/ip.h>
#include <onyx/net/netif.h>
#include <onyx/net/network.h>
#include <onyx/net/socket_table.h>
#include <onyx/net/tcp.h>
#include <onyx/net/udp.h>
#include <onyx/public/socket.h>
#include <onyx/random.h>
#include <onyx/utils.h>

namespace ip
{

namespace v4
{

bool needs_fragmentation(size_t packet_size, struct netif *netif)
{
    return packet_size > netif->mtu;
}

struct fragment
{
    packetbuf *original_packet;
    packetbuf *this_buf;
    uint16_t packet_off;
    uint16_t length;
    struct list_head list_node;
};

void free_frags(struct list_head *frag_list)
{
    list_for_every_safe (frag_list)
    {
        struct fragment *f = container_of(l, struct fragment, list_node);

        if (f->packet_off != 0)
        {
            /* Don't free when it's the first fragment, because it uses the original packetbuf */
            delete f->this_buf;
        }

        list_remove(l);

        delete f;
    }
}

struct send_info
{
    const inet_route &route;
    unsigned int type;
    unsigned int ttl;
    bool frags_following;
    uint16_t identification;

    send_info(const inet_route &r) : route{r}
    {
    }
};

#define IPV4_OFF_TO_FRAG_OFF(x) ((x) >> 3)
#define IPV4_FRAG_OFF_TO_OFF(x) ((x) << 3)

void setup_fragment(struct send_info *info, struct fragment *frag, struct ip_header *ip_header,
                    struct netif *netif)
{
    bool frags_following = info->frags_following;

    memset(ip_header, 0, sizeof(struct ip_header));
    /* Source ip and dest ip have been already endian-swapped as to
     * (ever so slightly) speed up fragmentation */
    ip_header->source_ip = info->route.src_addr.in4.s_addr;
    ip_header->dest_ip = info->route.dst_addr.in4.s_addr;
    ip_header->proto = info->type;
    ip_header->frag_info = htons((frags_following ? IPV4_FRAG_INFO_MORE_FRAGMENTS : 0) |
                                 (IPV4_OFF_TO_FRAG_OFF(frag->packet_off)));
    ip_header->identification = htons(info->identification);
    ip_header->ttl = info->ttl;
    ip_header->total_len = htons(frag->length + sizeof(struct ip_header));
    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->header_checksum = ipsum(ip_header, ip_header->ihl << 2);
}

int create_fragments(struct list_head *frag_list, packetbuf *buf, size_t payload_size,
                     struct send_info *sinfo, struct netif *netif)
{
    if (buf->needs_csum)
    {
        auto starting_csum = *buf->csum_offset;
        *(volatile may_alias_uint16_t *) buf->csum_offset = 0;
        auto csum = __ipsum_unfolded(buf->csum_start, buf->tail - buf->csum_start, starting_csum);

        *buf->csum_offset = ipsum_fold(csum);

        buf->needs_csum = 0;
        buf->csum_offset = nullptr;
        buf->csum_start = nullptr;
    }

    /* Okay, let's split stuff in multiple IPv4 fragments */
    uint16_t off = 0;

    /* Calculate the metadata's by subtracting payload_size from buf->length.
     * This will give the size of the ip header which is used together
     * with PACKET_MAX_HEAD_LENGTH, the overhead of each packet.
     */
    size_t packet_metadata_len = sizeof(ip_header);
    fragment *first_frag = nullptr;

    /* If the payload_size is 0 the mtu is almost certainly completely wrong */
    assert(payload_size != 0);

    while (payload_size != 0)
    {
        struct fragment *frag = new fragment{};
        if (!frag)
        {
            free_frags(frag_list);
            return -ENOMEM;
        }

        frag->original_packet = buf;

        /* Now we're computing this packet's length by adding the metadata's size and the
         * remaining payload size, clamping it, and then subsequently subtracing the
         * overhead of the metadata.
         */
        size_t total_size = packet_metadata_len + payload_size;

        if (total_size > netif->mtu)
        {
            total_size = netif->mtu;
        }

        /* Sizes need to be 8-byte aligned so the next fragment's offset can be valid
         * (fragment offsets are expressed in 8-byte units) */

        size_t this_payload_size =
            IPV4_FRAG_OFF_TO_OFF(IPV4_OFF_TO_FRAG_OFF(total_size - packet_metadata_len));

        if (!this_payload_size)
            this_payload_size = payload_size;

        frag->packet_off = off;
        frag->length = this_payload_size;

#if 0
		printk("Created fragment from %u size %lu\n", off, this_payload_size);
		printk("Remaining payload size: %lu\n", payload_size);
#endif

        /* Quick note regarding the following code: We account for the ip_header
         * a bunch of times because frag->length *does not* account for the header and
         * only takes the data's length into consideration; despite this, frag->length
         * + sizeof(ip_header) <= mtu.
         */

        bool first_packet = frag->packet_off == 0;
        if (first_packet)
        {
            first_frag = frag;
            frag->this_buf = buf;
        }
        else
        {
            auto header_length = packet_metadata_len + PACKET_MAX_HEAD_LENGTH;
            /* After allocating a new buffer, copy the packet */
            packetbuf *new_buf = new packetbuf;
            if (!new_buf || !new_buf->allocate_space(this_payload_size + header_length))
            {
                delete new_buf;
                delete frag;
                free_frags(frag_list);
                return -ENOMEM;
            }

            new_buf->reserve_headers(header_length);

            /* We add sizeof(ip_header) here because we're guaranteed to have pushed the ip_header,
             * down below, of the original buffer, before.
             */

            const uint8_t *old_packet_ptr = buf->data + sizeof(ip_header) + off;
            auto new_packet_ptr = new_buf->put(frag->length);

            memcpy(new_packet_ptr, old_packet_ptr, frag->length);
            frag->this_buf = new_buf;
        }

        struct ip_header *header = (ip_header *) frag->this_buf->push_header(sizeof(ip_header));
        frag->this_buf->net_header = (unsigned char *) header;

        sinfo->frags_following = !(payload_size == this_payload_size);
        setup_fragment(sinfo, frag, header, netif);

        list_add_tail(&frag->list_node, frag_list);

        payload_size -= this_payload_size;
        off += this_payload_size;
    }

#if 0
	printk("Frag length: %u\n", first_frag->length);
#endif

    buf->tail = buf->data + first_frag->length + sizeof(ip_header);

    buf->page_vec[0].length = buf->tail - (unsigned char *) buf->buffer_start;

#if 0
	printk("vec length: %u\n", buf->page_vec[0].length - buf->buffer_start_off());
#endif

    for (size_t i = 1; i < PACKETBUF_MAX_NR_PAGES + 1; i++)
    {
        if (!buf->page_vec[i].page)
            break;
        free_page(buf->page_vec[i].page);
        buf->page_vec[i].page = nullptr;
    }

    return 0;
}

static tx_type detect_tx_type(const inet_route &route)
{
    if (route.flags & INET4_ROUTE_FLAG_BROADCAST) [[unlikely]]
        return tx_type::broadcast;
    if (route.flags & INET4_ROUTE_FLAG_MULTICAST) [[unlikely]]
        return tx_type::multicast;

    return tx_type::unicast;
}

int send_fragment(const inet_route &route, fragment *frag, netif *nif)
{
    auto buf = frag->this_buf;
    auto type = detect_tx_type(route);
    int st = 0;

    const void *hwaddr = nullptr;

    if (type != tx_type::broadcast) [[likely]]
    {
        if (route.dst_hw->flags & NEIGHBOUR_FLAG_BADENTRY)
            return -EHOSTUNREACH;
        hwaddr = route.dst_hw->hwaddr().data();
    }

    if ((st = nif->dll_ops->setup_header(buf, type, tx_protocol::ipv4, nif, hwaddr)) < 0)
        [[unlikely]]
        return st;

    return netif_send_packet(nif, buf);
}

int do_fragmentation(struct send_info *sinfo, size_t payload_size, packetbuf *buf,
                     struct netif *netif)
{
    struct list_head frags = LIST_HEAD_INIT(frags);
    int st = create_fragments(&frags, buf, payload_size, sinfo, netif);

    if (st < 0)
    {
        errno = -st;
        return -1;
    }

    list_for_every (&frags)
    {
        struct fragment *frag = container_of(l, struct fragment, list_node);

        st = send_fragment(sinfo->route, frag, netif);

        if (st < 0)
            goto out;
    }

out:
    free_frags(&frags);

    return st;
}

uint16_t identification_counter = 0;

static uint16_t allocate_id(void)
{
    return __atomic_fetch_add(&identification_counter, 1, __ATOMIC_CONSUME);
}

int send_packet(const iflow &flow, packetbuf *buf, cul::slice<ip_option> options)
{
    size_t payload_size = buf->length();
    auto netif = flow.nif;

    struct send_info sinfo
    {
        flow.route
    };
    /* Dest ip and sender ip are already in network order */
    sinfo.ttl = flow.ttl;
    sinfo.type = flow.protocol;
    sinfo.frags_following = false;

    if (needs_fragmentation(buf->length(), netif))
    {
        /* TODO: Support ISO(IP segmentation offloading) */
        sinfo.identification = allocate_id();
        return do_fragmentation(&sinfo, payload_size, buf, netif);
    }

    ip_header *iphdr = (ip_header *) buf->net_header;
    if (!iphdr)
        iphdr = (ip_header *) buf->push_header(sizeof(ip_header));

    /* Let's reuse code by creating a single fragment struct on the stack */
    struct fragment frag;
    frag.length = payload_size;
    frag.packet_off = 0;
    frag.this_buf = buf;
    buf->net_header = (unsigned char *) iphdr;

    setup_fragment(&sinfo, &frag, iphdr, netif);

    return send_fragment(flow.route, &frag, netif);
}

bool valid_packet(struct ip_header *header, size_t size)
{
    if (sizeof(struct ip_header) > size)
        return false;

    if (header->version != 4)
        return false;

    if (header->ihl < 5)
        return false;

    if (ntohs(header->total_len) > size)
        return false;

    return true;
}

/**
 * @brief Checks if an address is a multicast addr
 * Does it by checking the most signficant 8 bits
 * for a class D address
 *
 * @param addr IPv4 address
 * @returns True if multicast, else false
 */
constexpr bool addr_is_multicast(in_addr_t addr)
{
    return (addr & 0b11110000) == 0b11100000;
}

/**
 * @brief Checks if addr is the local broadcast addr
 *
 * @param addr IPv4 address
 * @returns True if local broadcast (255.255.255.255), else false
 */
constexpr bool addr_is_local_broadcast(in_addr_t addr)
{
    return addr == INADDR_BROADCAST;
}

/**
 * @brief Checks if addr is a directed broadcast address
 * These addresses are the all-ones address in a subnet
 * e.g: 192.168.1.0/24 subnet, 192.168.1.255 is the broadcast addr.
 *
 * @param addr IPv4 addr
 * @param r Route
 * @returns True if directed broadcast addr, else false
 */
constexpr bool addr_is_directed_broadcast(in_addr_t addr, const inet_route &r)
{
    in_addr_t broadcast_mask = ~r.mask.in4.s_addr;
    return (r.dst_addr.in4.s_addr & broadcast_mask) == broadcast_mask;
}

/**
 * @brief Checks if the address is a broadcast address in general
 *
 * @param addr IPv4 address
 * @param r Route
 * @returns True if broadcast, else false
 */
constexpr bool addr_is_broadcast(in_addr_t addr, const inet_route &r)
{
    return addr_is_local_broadcast(addr) || addr_is_directed_broadcast(addr, r);
}

int handle_packet(netif *nif, packetbuf *buf)
{
    struct ip_header *header = (ip_header *) buf->data;

    if (!valid_packet(header, buf->length()))
    {
        return -EINVAL;
    }

    buf->net_header = (unsigned char *) header;
    buf->domain = AF_INET;
    auto iphdr_len = ip_header_length(header);

    buf->data += iphdr_len;

    /* Adjust tail to point at the end of the ipv4 packet */
    buf->tail = (unsigned char *) header + ntohs(header->total_len);

    inet_route route;
    route.dst_addr.in4.s_addr = header->dest_ip;
    route.gateway_addr = {};
    route.src_addr.in4.s_addr = header->source_ip;
    route.nif = nif;
    route.mask.in4.s_addr =
        0xffffff00; // NOT CORRECT. but will do for now. We need ipv4 addresses with subnets
    route.flags = 0;

    if (addr_is_multicast(header->dest_ip))
    {
        route.flags |= INET4_ROUTE_FLAG_MULTICAST;
    }
    else if (addr_is_broadcast(header->dest_ip, route))
    {
        route.flags |= INET4_ROUTE_FLAG_BROADCAST;
    }

    if (header->proto == IPPROTO_UDP)
        return udp_handle_packet(route, buf);
    else if (header->proto == IPPROTO_TCP)
        return tcp_handle_packet(route, buf);
    else if (header->proto == IPPROTO_ICMP)
        return icmp::handle_packet(route, buf);
    else
    {
        /* Oh, no, an unhandled protocol! Send an ICMP error message */

        icmp::dst_unreachable_info dst_un;
        dst_un.code = ICMP_CODE_PROTO_UNREACHABLE;
        dst_un.iphdr = header;
        unsigned char *dgram;
        unsigned char bytes[8] = {0, 0, 0, 0, 0, 0, 0, 0};

        /* We perform this check to make sure we don't leak memory */
        if (buf->length() >= 8)
            dgram = (unsigned char *) header + iphdr_len;
        else
            dgram = bytes;

        dst_un.dgram = dgram;
        dst_un.next_hop_mtu = 0;

        icmp::send_dst_unreachable(dst_un, nif);
    }

    return 0;
}

constexpr bool is_proto_without_ports(int proto)
{
    return proto == IPPROTO_ICMP;
}

int proto_family::bind_internal(sockaddr_in *in, inet_socket *sock)
{
    auto proto_info = sock->proto_info;
    auto sock_table = proto_info->get_socket_table();

    inet_sock_address addr{*in};
    fnv_hash_t hash = 0;
    int extra_flags = sock->connected ? GET_SOCKET_DSTADDR_VALID : 0;

    // For non-connected sockets that just called bind(), sock->dest_addr will be all 0's
    // For listening sockets that just got created, the sock->dest_addr will be filled,
    // and therefore will not conflict
    const socket_id id(sock->proto, AF_INET, addr, sock->connected ? sock->dest_addr : addr);

    /* Some protocols have no concept of ports, like ICMP, for example.
     * These are special cases that require that in->sin_port = 0 **and**
     * we do not allocate a port, like we would for standard sin_port = 0.
     */
    bool proto_has_no_ports = is_proto_without_ports(sock->proto);

    if (proto_has_no_ports && in->sin_port != 0)
        return -EINVAL;

    if (in->sin_port != 0 || proto_has_no_ports)
    {
        if (!proto_has_no_ports && !inet_has_permission_for_port(in->sin_port))
            return -EPERM;

        hash = inet_socket::make_hash_from_id(id);

        sock_table->lock(hash);

        /* Check if there's any socket bound to this address yet, if we're not talking about ICMP.
         * ICMP allows you to bind multiple sockets, as they'll all receive the same packets.
         */
        if (!proto_has_no_ports &&
            sock_table->get_socket(id,
                                   GET_SOCKET_CHECK_EXISTENCE | GET_SOCKET_UNLOCKED | extra_flags))
        {
            sock_table->unlock(hash);
            return -EADDRINUSE;
        }
    }
    else
    {
        /* Lets try to allocate a new ephemeral port for us */
        in->sin_port = allocate_ephemeral_port(addr, sock, AF_INET);
        hash = inet_socket::make_hash_from_id(id);
    }

    sock->src_addr = addr;

    /* Note: locks need to be held */
    bool success = sock_table->add_socket(sock, ADD_SOCKET_UNLOCKED);

    sock_table->unlock(hash);

    return success ? 0 : -ENOMEM;
}

static constexpr bool is_bind_any(in_addr_t addr)
{
    /* For historical reasons, INADDR_ANY == INADDR_BROADCAST (linux's ip(7)).
     * Linux isn't alone in this and we should strive for compatibility.
     */
    return addr == INADDR_ANY || addr == INADDR_BROADCAST;
}

int proto_family::bind(sockaddr *addr, socklen_t len, inet_socket *sock)
{
    if (len != sizeof(sockaddr_in))
        return -EINVAL;

    sockaddr_in *in = (sockaddr_in *) addr;

    int st = 0;

    if (!sock->validate_sockaddr_len_pair(addr, len))
        return -EINVAL;

    st = bind_internal(in, sock);

    if (st < 0)
        return st;

    sock->bound = true;
    return 0;
}

int proto_family::bind_any(inet_socket *sock)
{
    sockaddr_in in = {};
    in.sin_family = AF_INET;
    in.sin_addr.s_addr = INADDR_ANY;
    in.sin_port = 0;

    return bind((sockaddr *) &in, sizeof(sockaddr_in), sock);
}

void proto_family::unbind(inet_socket *sock)
{
    sock->proto_info->get_socket_table()->remove_socket(sock, 0);
}

rwlock routing_table_lock;
cul::vector<shared_ptr<inet4_route>> routing_table;

expected<inet_route, int> proto_family::route(const inet_sock_address &from,
                                              const inet_sock_address &to, int domain)
{
    /* domain only matters for IPv6 sockets that need to check if it's running on ipv4-mapped */
    (void) domain;
    netif *required_netif = nullptr;
    /* If the source address specifies an interface, we need to use that one. */
    if (!is_bind_any(from.in4.s_addr))
    {
        required_netif = netif_get_from_addr(from, AF_INET);
        if (!required_netif)
            return unexpected<int>{-ENETDOWN};
    }

    /* Else, we're searching through the routing table to find the best interface to use in order
     * to reach our destination
     */
    shared_ptr<inet4_route> best_route;
    int highest_metric = 0;
    auto dest = to.in4.s_addr;

    // TODO: Multicast
    if (addr_is_local_broadcast(dest))
    {
        inet_route r;
        r.dst_addr.in4.s_addr = dest;
        r.src_addr.in4.s_addr = from.in4.s_addr;
        r.flags = INET4_ROUTE_FLAG_BROADCAST;
        r.mask.in4.s_addr = INADDR_BROADCAST;
        r.gateway_addr.in4 = {};
        r.nif = required_netif ? required_netif : netif_choose();

        if (!r.nif)
            return unexpected<int>{-ENETDOWN};

        return r;
    }

    rw_lock_read(&routing_table_lock);

    for (auto &r : routing_table)
    {
        /* Do a bitwise and between the destination address and the mask
         * If the result = r.dest, we can use this interface.
         */
#if 0
		printk("dest %x, mask %x, supposed dest %x\n", dest, r->mask, r->dest);
#endif
        if ((dest & r->mask) != r->dest)
            continue;

        if (required_netif && r->nif != required_netif)
            continue;
#if 0
		printk("%s is good\n", r->nif->name);
		printk("is loopback set %u\n", r->nif->flags & NETIF_LOOPBACK);
#endif

        int mods = 0;
        if (r->flags & INET4_ROUTE_FLAG_GATEWAY)
            mods--;

        if (r->metric + mods > highest_metric)
        {
            best_route = r;
            highest_metric = r->metric;
        }
    }

    rw_unlock_read(&routing_table_lock);

    if (!best_route)
    {
        return unexpected<int>{-ENETUNREACH};
    }

    inet_route r;
    r.dst_addr.in4 = to.in4;
    r.nif = best_route->nif;
    r.mask.in4.s_addr = best_route->mask;
    r.src_addr.in4.s_addr = r.nif->local_ip.sin_addr.s_addr;
    r.flags = best_route->flags;
    r.gateway_addr.in4.s_addr = best_route->gateway;

    if (addr_is_broadcast(to.in4.s_addr, r))
    {
        r.flags |= INET4_ROUTE_FLAG_BROADCAST;
    }
    else if (addr_is_multicast(to.in4.s_addr))
    {
        r.flags |= INET4_ROUTE_FLAG_MULTICAST;
    }

    auto to_resolve = r.dst_addr.in4.s_addr;

    if (r.flags & INET4_ROUTE_FLAG_GATEWAY)
    {
        to_resolve = r.gateway_addr.in4.s_addr;
    }

    auto res = arp_resolve_in(to_resolve, r.nif);

    if (res.has_error()) [[unlikely]]
    {
        return unexpected<int>(-ENETUNREACH);
    }

    r.dst_hw = res.value();

    return r;
}

bool add_route(inet4_route &route)
{
    rw_lock_write(&routing_table_lock);

    auto ptr = make_shared<inet4_route>();
    if (!ptr)
        return false;

    memcpy(ptr.get(), &route, sizeof(route));

    bool st = routing_table.push_back(ptr);

    rw_unlock_write(&routing_table_lock);

    return st;
}

static proto_family v4_protocol;

inet_proto_family *get_v4_proto()
{
    return &v4_protocol;
}

socket *create_socket(int type, int protocol)
{
    if (protocol == IPPROTO_ICMPV6)
        return errno = EAFNOSUPPORT, nullptr;

    auto sock = ip::choose_protocol_and_create(type, protocol);

    if (sock)
        sock->proto_domain = &v4_protocol;

    return sock;
}

} // namespace v4
} // namespace ip

bool inet_has_permission_for_port(in_port_t port)
{
    port = ntohs(port);

    if (port >= inet_min_unprivileged_port)
        return true;

    struct creds *c = creds_get();

    bool ret = c->euid == 0;

    creds_put(c);

    return ret;
}

/* Modifies *addr too */
bool inet_socket::validate_sockaddr_len_pair(sockaddr *addr, socklen_t len)
{
    bool v6 = domain == AF_INET6;

    if (!v6)
        return validate_sockaddr_len_pair_v4(reinterpret_cast<sockaddr_in *>(addr), len);
    else
        return validate_sockaddr_len_pair_v6(reinterpret_cast<sockaddr_in6 *>(addr), len);
}

bool inet_socket::validate_sockaddr_len_pair_v4(sockaddr_in *addr, socklen_t len)
{
    if (len != sizeof(sockaddr_in))
        return false;

    return check_sockaddr_in(addr);
}

void inet_socket::unbind()
{
    if (!bound)
        return;

    auto proto_fam = get_proto_fam();

    proto_fam->unbind(this);
}

void inet_socket::append_inet_rx_pbuf(packetbuf *buf)
{
    scoped_lock g{rx_packet_list_lock};

    buf->ref();

    list_add_tail(&buf->list_node, &rx_packet_list);

    wait_queue_wake_all(&rx_wq);
}

inet_socket::~inet_socket()
{
    unbind();

    list_for_every_safe (&rx_packet_list)
    {
        auto buf = list_head_cpp<packetbuf>::self_from_list_head(l);
        list_remove(&buf->list_node);

        buf->unref();
    }
}

int inet_socket::setsockopt_inet4(int level, int opt, const void *optval, socklen_t len)
{
    switch (opt)
    {
        case IP_TTL: {
            auto ex = get_socket_option<int>(optval, len);

            if (ex.has_error())
                return ex.error();

            auto ttl = ex.value();

            if (ttl < 0 || ttl > 255)
                return -EINVAL;

            this->ttl = ttl;
            return 0;
        }
    }

    return -ENOPROTOOPT;
}

int inet_socket::getsockopt_inet4(int level, int opt, void *optval, socklen_t *len)
{
    switch (opt)
    {
        case IP_TTL:
            return put_option(ttl, optval, len);
    }

    return -ENOPROTOOPT;
}

int inet_socket::setsockopt_inet(int level, int opt, const void *optval, socklen_t len)
{
    return domain == AF_INET ? setsockopt_inet4(level, opt, optval, len)
                             : setsockopt_inet6(level, opt, optval, len);
}

int inet_socket::getsockopt_inet(int level, int opt, void *optval, socklen_t *len)
{
    return domain == AF_INET ? getsockopt_inet4(level, opt, optval, len)
                             : getsockopt_inet6(level, opt, optval, len);
}

size_t inet_socket::get_headers_len() const
{
    if (effective_domain() == AF_INET6)
        return sizeof(ip6hdr); /* TODO: Extensions */
    else
        return sizeof(ip_header);
}

bool inet_socket::needs_fragmenting(netif *nif, packetbuf *buf) const
{
    return nif->mtu < buf->length() + get_headers_len();
}

/**
 * @brief Check if we can offload the checksumming
 *        Usually, this should be possible if there's no fragmenting needed and the interface
 *        supports such a thing.
 * @param nif Network interface
 * @param buf Packet that we're trying to send
 * @return True if possible, else false
 */
bool inet_socket::can_offload_csum(netif *nif, packetbuf *buf) const
{
    return nif->flags & NETIF_SUPPORTS_CSUM_OFFLOAD && !needs_fragmenting(nif, buf);
}

bool inet_proto_family::add_socket(inet_socket *sock)
{
    auto proto_info = sock->proto_info;
    auto sock_table = proto_info->get_socket_table();
    return sock_table->add_socket(sock, ADD_SOCKET_UNLOCKED);
}
