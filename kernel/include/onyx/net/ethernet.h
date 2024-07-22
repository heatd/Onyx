/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_NET_ETHERNET_H
#define _ONYX_NET_ETHERNET_H

#include <stdint.h>

#include <onyx/net/dll.h>
#include <onyx/net/netif.h>
#include <onyx/packetbuf.h>

#define PROTO_IPV4 ((uint16_t) 0x800)
#define PROTO_ARP  ((uint16_t) 0x806)
#define PROTO_IPV6 ((uint16_t) 0x86DD)

#define ETH_ALEN 6

struct eth_header
{
    uint8_t mac_dest[ETH_ALEN];
    uint8_t mac_source[ETH_ALEN];
    uint16_t ethertype;
} __attribute__((packed));

typedef struct
{
    uint8_t interpacket_gap[12];
    uint32_t crc32;
} __attribute__((packed)) ethernet_footer_t;

class eth_dll_ops : public data_link_layer_ops
{
public:
    int setup_header(packetbuf *buf, tx_type type, tx_protocol proto, netif *nif,
                     const void *dst_hw) override;
    int rx_packet(netif *nif, packetbuf *buf) override;
};

extern eth_dll_ops eth_ops;

#endif
