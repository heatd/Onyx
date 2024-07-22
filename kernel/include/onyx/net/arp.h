/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_NET_ARP_H
#define _ONYX_NET_ARP_H

#include <stdint.h>

#include <onyx/net/ethernet.h>
#include <onyx/net/neighbour.h>
#include <onyx/packetbuf.h>

#include <onyx/expected.hpp>

#define ARP_ETHERNET      ((uint16_t) 1)
#define ARP_HLEN_ETHERNET ((uint16_t) 6)
#define ARP_PLEN_IPV4     ((uint16_t) 4)
#define ARP_PLEN_IPV6     ((uint16_t) 6)
#define ARP_OP_REQUEST    ((uint16_t) 1)
#define ARP_OP_REPLY      ((uint16_t) 2)

typedef struct
{
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t operation;
    uint8_t sender_hw_address[6];
    uint32_t sender_proto_address;
    uint8_t target_hw_address[6];
    uint32_t target_proto_address;

} __attribute__((packed)) arp_request_t;

struct netif;

expected<shared_ptr<neighbour>, int> arp_resolve_in(uint32_t ip, struct netif *netif);
int arp_handle_packet(netif *netif, packetbuf *buf);

#endif
