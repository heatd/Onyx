/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_NET_ETHERNET_H
#define _ONYX_NET_ETHERNET_H

#include <stdint.h>

#include <onyx/net/netif.h>
#include <onyx/packetbuf.h>

#define PROTO_IPV4 ((uint16_t) 0x800)
#define PROTO_ARP ((uint16_t) 0x806)
#define PROTO_IPV6 ((uint16_t) 0x86DD)

struct eth_header
{
	uint8_t mac_dest[6];
	uint8_t mac_source[6];
	uint16_t ethertype;
} __attribute__((packed));

typedef struct
{
	uint8_t interpacket_gap[12];
	uint32_t crc32;
} __attribute__((packed)) ethernet_footer_t;

#define LITTLE_TO_BIG16(n) ((n >> 8) | (n << 8))
#define LITTLE_TO_BIG32(n) ((n >> 24) & 0xFF) | ((n << 8) & 0xFF0000) | \
			   ((n >> 8) & 0xFF00) | ((n << 24) & 0xFF000000)

typedef int (*device_send_packet)(const void*, uint16_t);

#ifdef __cplusplus
extern "C" {
#endif

int eth_send_packet(char *destmac, packetbuf *buf, uint16_t protocol, struct netif *netif);

#ifdef __cplusplus
}
#endif
#endif
