/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/byteswap.h>
#include <onyx/compiler.h>
#include <onyx/err.h>
#include <onyx/log.h>
#include <onyx/net/arp.h>
#include <onyx/net/ethernet.h>
#include <onyx/net/ip.h>
#include <onyx/net/neighbour.h>
#include <onyx/net/netif.h>
#include <onyx/spinlock.h>

#include <onyx/memory.hpp>

static neighbour_table arp_table{AF_INET};
static constexpr hrtime_t arp_response_timeout = 250 * NS_PER_MS;

/* 20 minutes in milis */
static constexpr unsigned long arp_validity_time_ms = 1200000;

static int arp_do_request(netif *netif, packetbuf *packet, arp_request_t *arp_hdr)
{
    auto target_addr = arp_hdr->target_proto_address;
    uint8_t hw_address[6];

    /* TODO */
    (void) arp_validity_time_ms;
    (void) arp_response_timeout;

    if (netif->local_ip.sin_addr.s_addr == target_addr)
    {
        memcpy(hw_address, netif->mac_address, 6);
    }
    else
        return 0; // Don't handle it

    auto buf = make_unique<packetbuf>();
    if (!buf)
        return -ENOMEM;

    if (!buf->allocate_space(sizeof(arp_request_t) + PACKET_MAX_HEAD_LENGTH))
        return -ENOMEM;

    buf->reserve_headers(sizeof(arp_request_t) + PACKET_MAX_HEAD_LENGTH);

    auto arp = reinterpret_cast<arp_request_t *>(buf->push_header(sizeof(arp_request_t)));
    memset(arp, 0, sizeof(arp_request_t));
    arp->htype = htons(ARP_ETHERNET);
    arp->ptype = 0x0008;
    arp->hlen = ARP_HLEN_ETHERNET;
    arp->plen = ARP_PLEN_IPV4;
    arp->operation = htons(ARP_OP_REPLY);

    memcpy(arp->target_hw_address, arp_hdr->sender_hw_address, 6);
    arp->sender_proto_address = target_addr;
    memcpy(arp->sender_hw_address, hw_address, 6);
    arp->target_proto_address = arp_hdr->sender_proto_address;
    if (int st = netif->dll_ops->setup_header(buf.get(), tx_type::unicast, tx_protocol::arp, netif,
                                              arp_hdr->sender_hw_address);
        st < 0)
        return st;

    return netif_send_packet(netif, buf.get());
}

static int arp_resolve(struct neighbour *neigh, struct netif *netif);

static const struct neigh_ops arp_ops = {
    .resolve = arp_resolve,
    .output = ip_finish_output,
};

int arp_handle_packet(netif *netif, packetbuf *buf)
{
    struct neighbour *neigh;
    int added;
    arp_request_t *arp = (arp_request_t *) pbf_pull(buf, sizeof(arp_request_t));
    if (!arp)
        return -1;

    auto op = htons(arp->operation);

    if (op == ARP_OP_REQUEST)
        return arp_do_request(netif, buf, arp);

    if (op != ARP_OP_REPLY)
        return 0;

    in_addr_t req_ip = arp->sender_proto_address;
    union neigh_proto_addr addr;
    addr.in4addr.s_addr = req_ip;

    neigh = neigh_add(&arp_table, &addr, GFP_ATOMIC, &arp_ops, &added);
    if (!neigh)
        return 0;
    neigh_complete_lookup(neigh, arp->sender_hw_address, ETH_ALEN);
    return 0;
}

static int arp_resolve(struct neighbour *neigh, struct netif *netif)
{
    in_addr_t target_addr = neigh->proto_addr.in4addr.s_addr;

    if (target_addr == INADDR_BROADCAST || target_addr == INADDR_LOOPBACK ||
        netif->flags & NETIF_LOOPBACK)
    {
        const unsigned char bcast_eth[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        const unsigned char loopback_eth[ETH_ALEN] = {};
        __neigh_complete_lookup(neigh, target_addr == INADDR_BROADCAST ? bcast_eth : loopback_eth,
                                ETH_ALEN);
        return 0;
    }

    auto buf = make_unique<packetbuf>();
    if (!buf)
        return -ENOMEM;

    if (!buf->allocate_space(sizeof(arp_request_t) + PACKET_MAX_HEAD_LENGTH))
        return -ENOMEM;

    buf->reserve_headers(sizeof(arp_request_t) + PACKET_MAX_HEAD_LENGTH);

    auto arp = reinterpret_cast<arp_request_t *>(buf->push_header(sizeof(arp_request_t)));
    memset(arp, 0, sizeof(arp_request_t));
    arp->htype = htons(ARP_ETHERNET);
    arp->ptype = 0x0008;
    arp->hlen = ARP_HLEN_ETHERNET;
    arp->plen = ARP_PLEN_IPV4;
    arp->operation = htons(ARP_OP_REQUEST);

    memcpy(&arp->sender_hw_address, &netif->mac_address, 6);
    arp->target_hw_address[0] = 0xFF;
    arp->target_hw_address[1] = 0xFF;
    arp->target_hw_address[2] = 0xFF;
    arp->target_hw_address[3] = 0xFF;
    arp->target_hw_address[4] = 0xFF;
    arp->target_hw_address[5] = 0xFF;
    arp->sender_proto_address = netif->local_ip.sin_addr.s_addr;
    arp->target_proto_address = neigh->proto_addr.in4addr.s_addr;
    if (int st = netif->dll_ops->setup_header(buf.get(), tx_type::broadcast, tx_protocol::arp,
                                              netif, nullptr);
        st < 0)
        return st;

    return netif_send_packet(netif, buf.get());
}

struct neighbour *arp_resolve_in(uint32_t ip, struct netif *netif)
{
    struct neighbour *neigh;
    int added;
    union neigh_proto_addr addr;
    addr.in4addr.s_addr = ip;

    neigh = neigh_add(&arp_table, &addr, GFP_ATOMIC, &arp_ops, &added);
    if (!neigh)
        return (struct neighbour *) ERR_PTR(-ENOMEM);

    if (neigh_needs_resolve(neigh))
        neigh_start_resolve(neigh, netif);
    return neigh;
}
