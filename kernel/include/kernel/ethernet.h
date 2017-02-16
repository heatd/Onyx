/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/

#ifndef _ETHERNET_H
#define _ETHERNET_H

#include <stdint.h>

#define PROTO_IPV4 ((uint16_t)0x800)
#define PROTO_ARP ((uint16_t)0x806)
#define PROTO_IPV6 ((uint16_t)0x86DD)

typedef struct
{
	uint8_t mac_dest[6];
	uint8_t mac_source[6];
	uint16_t ethertype;
	uint8_t payload[0];
} __attribute__((packed)) ethernet_header_t;

typedef struct
{
	uint8_t interpacket_gap[12];
	uint32_t crc32;
} __attribute__((packed)) ethernet_footer_t;

#define LITTLE_TO_BIG16(n) ((n >> 8) | (n << 8))
#define LITTLE_TO_BIG32(n) ((n >> 24) & 0xFF) | ((n << 8) & 0xFF0000) | ((n >> 8) & 0xFF00) | ((n << 24) & 0xFF000000)
extern char mac_address[6];
extern char router_mac[6];
typedef int (*device_send_packet)(const void*, uint16_t);

void eth_set_packet_buf(uint8_t *buf);
void eth_set_packet_len(uint16_t len);
void eth_set_dev_send_packet(device_send_packet);
int eth_send_packet(char *destmac, char *payload, uint16_t len, uint16_t protocol);
int ethernet_handle_packet(uint8_t *packet, uint16_t len);
int ethernet_init();
void eth_set_router_mac(char* mac);
#endif
