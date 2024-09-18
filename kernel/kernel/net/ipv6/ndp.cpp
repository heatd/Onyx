/*
 * Copyright (c) 2020 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Don't change the include order! Maybe TOFIX? */
#include <netinet/icmp6.h>

#include <onyx/byteswap.h>
#include <onyx/compiler.h>
#include <onyx/err.h>
#include <onyx/log.h>
#include <onyx/net/ethernet.h>
#include <onyx/net/icmpv6.h>
#include <onyx/net/ip.h>
#include <onyx/net/neighbour.h>
#include <onyx/net/netif.h>
#include <onyx/spinlock.h>

#include <onyx/memory.hpp>

struct icmp6_opt_header
{
    uint8_t type;

    /* In units of 8-octets */
    uint8_t length;
};

struct icmp6_source_link_layer_opt
{
    icmp6_opt_header hdr;
    unsigned char hwaddr[];
};

/* FIXME: The ndp table should be per interface */

static neighbour_table ndp_table{AF_INET6};

int ndp_submit_request(struct neighbour *neigh, struct netif *netif);

const struct neigh_ops ndp_ops = {
    .resolve = ndp_submit_request,
    .output = ip6_finish_output,
};

static constexpr hrtime_t ndp_response_timeout = 250 * NS_PER_MS;

/* 20 minutes in milis */
static constexpr unsigned long ndp_validity_time_ms = 1200000;

int ndp_handle_na(netif *netif, packetbuf *buf)
{
    (void) ndp_response_timeout;
    (void) ndp_validity_time_ms;
    if (buf->length() < sizeof(nd_neighbor_advert))
        return -EINVAL;

    auto ndp = (struct nd_neighbor_advert *) buf->data;
    int added;
    neigh_proto_addr addr;
    addr.in6addr = ndp->nd_na_target;

    struct neighbour *neigh = neigh_add(&ndp_table, &addr, GFP_ATOMIC, &ndp_ops, &added);
    if (!neigh)
        return -ENOMEM;

    const char *optptr = (const char *) (ndp + 1);
    ssize_t options_len = buf->length() - sizeof(nd_neighbor_solicit);

    const unsigned char *target = nullptr;
    /* Each option is at least 8 bytes long */
    while (options_len >= 8)
    {
        auto hdr = (const icmp6_opt_header *) optptr;
        auto length = hdr->length << 3;
        if (length > options_len)
        {
            return -EINVAL;
        }

        switch (hdr->type)
        {
            case ND_OPT_TARGET_LINKADDR: {
                if (length != 8)
                    return -EINVAL;
                target = (const unsigned char *) optptr + 2;
            }
        }

        optptr += length;
        options_len -= length;
    }

    if (!target)
        return 0;

    neigh_complete_lookup(neigh, target, ETH_ALEN);
    return 0;
}

int ndp_handle_ns(netif *nif, packetbuf *buf)
{
    if (buf->length() < sizeof(nd_neighbor_solicit))
        return -EINVAL;

    auto iphdr = (const ip6hdr *) buf->net_header;

    auto ndp = (struct nd_neighbor_solicit *) buf->data;

    neigh_proto_addr addr;
    addr.in6addr = ndp->nd_ns_target;

    bool is_us = netif_find_v6_address(nif, addr.in6addr);

    if (!is_us)
    {
        /* TODO */
        return 0;
    }

    constexpr size_t source_link_layer_opt = sizeof(icmp6_source_link_layer_opt) + 6;
    char buf_[sizeof(nd_neighbor_solicit) + source_link_layer_opt];
    nd_neighbor_advert *sol = new (buf_) nd_neighbor_advert;
    sol->nd_na_target = addr.in6addr;
    sol->nd_na_flags_reserved = ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE;

    auto *opt = new (&buf_[sizeof(nd_neighbor_advert)]) icmp6_source_link_layer_opt;
    opt->hdr.type = ND_OPT_TARGET_LINKADDR;
    opt->hdr.length = 1;

    const auto &mac = nif->mac_address;
    memcpy(&opt->hwaddr, mac, 6);

    auto from = inet_sock_address{in6addr_any, 0, nif->if_id};
    auto to = inet_sock_address{iphdr->src_addr, 0, nif->if_id};

    auto route = ip::v6::get_v6_proto()->route(from, to, AF_INET6);
    if (route.has_error())
        return route.error();

    // panic("flags %lx", sol->nd_na_flags_reserved);

    icmpv6::send_data data{ICMPV6_NEIGHBOUR_ADVERT, 0, route.value(), sol->nd_na_flags_reserved};

    return icmpv6::send_packet(data, cul::slice<unsigned char>{(unsigned char *) &sol->nd_na_target,
                                                               sizeof(buf_) - sizeof(icmp6_hdr)});
}

int ndp_handle_packet(netif *netif, packetbuf *buf)
{
    if (buf->length() < sizeof(icmpv6_header))
        return -EINVAL;

    auto icmp_header = (const icmpv6_header *) buf->data;

    if (icmp_header->type == ICMPV6_NEIGHBOUR_ADVERT)
        return ndp_handle_na(netif, buf);
    else if (icmp_header->type == ICMPV6_NEIGHBOUR_SOLICIT)
        return ndp_handle_ns(netif, buf);
    else
        __builtin_unreachable();
    /* TODO: Handle all the intricacies of the protocol */

    return 0;
}

const in6_addr solicited_node_prefix = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0x00};

in6_addr solicited_node_address(const in6_addr &our_address)
{
    /* Per rfc4291, the solicited node address is formed by taking the low 24-bits of an address and
     * appending them to the solicited_node_prefix(see above).
     */
    auto ret = solicited_node_prefix;
    for (int i = 0; i < 3; i++)
        ret.s6_addr[13 + i] = our_address.s6_addr[13 + i];

    return ret;
}

int ndp_submit_request(struct neighbour *neigh, struct netif *netif)
{
    const in6_addr &target_addr = neigh->proto_addr.in6addr;
    if (target_addr == in6addr_loopback || netif->flags & NETIF_LOOPBACK)
    {
        const unsigned char loopback_eth[ETH_ALEN] = {};
        __neigh_complete_lookup(neigh, loopback_eth, ETH_ALEN);
        return 0;
    }

    constexpr size_t source_link_layer_opt = sizeof(icmp6_source_link_layer_opt) + 6;
    char buf_[sizeof(nd_neighbor_solicit) + source_link_layer_opt];
    nd_neighbor_solicit *sol = new (buf_) nd_neighbor_solicit;
    sol->nd_ns_target = target_addr;

    auto *opt = new (&buf_[sizeof(nd_neighbor_solicit)]) icmp6_source_link_layer_opt;
    opt->hdr.type = ND_OPT_SOURCE_LINKADDR;
    opt->hdr.length = 1;

    const auto &mac = netif->mac_address;
    memcpy(&opt->hwaddr, mac, 6);

    auto from = inet_sock_address{in6addr_any, 0, netif->if_id};
    auto to = inet_sock_address{solicited_node_address(target_addr), 0, netif->if_id};

    auto route = ip::v6::get_v6_proto()->route(from, to, AF_INET6);
    if (route.has_error())
        return route.error();

    icmpv6::send_data data{ICMPV6_NEIGHBOUR_SOLICIT, 0, route.value(), 0};

    return icmpv6::send_packet(data, cul::slice<unsigned char>{(unsigned char *) &sol->nd_ns_target,
                                                               sizeof(buf_) - sizeof(icmp6_hdr)});
}

struct neighbour *ndp_resolve(const in6_addr &ip, struct netif *netif)
{
    struct neighbour *neigh;
    int added;
    union neigh_proto_addr addr;
    addr.in6addr = ip;

    neigh = neigh_add(&ndp_table, &addr, GFP_ATOMIC, &ndp_ops, &added);
    if (!neigh)
        return (struct neighbour *) ERR_PTR(-ENOMEM);

    if (neigh_needs_resolve(neigh))
        neigh_start_resolve(neigh, netif);
    return neigh;
}
