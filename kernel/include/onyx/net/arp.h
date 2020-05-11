/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_NET_ARP_H
#define _ONYX_NET_ARP_H

#include <stdint.h>

#include <onyx/net/ethernet.h>

#define ARP_ETHERNET ((uint16_t)1)
#define ARP_HLEN_ETHERNET ((uint16_t)6)
#define ARP_PLEN_IPV4 ((uint16_t)4)
#define ARP_PLEN_IPV6 ((uint16_t)6)
#define ARP_OP_REQUEST ((uint16_t)1)
#define ARP_OP_REPLY ((uint16_t)2) 
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

#define ARP_FLAG_RESOLVED		(1 << 0)
struct arp_cache
{
	int flags;
	uint32_t ip;
	unsigned char mac[6];
	struct arp_cache *next;
};
struct arp_hashtable
{
	struct arp_cache *entries[255];
};

struct netif;
#ifdef __cplusplus
extern "C" {
#endif

int arp_resolve_in(uint32_t ip, unsigned char *mac, struct netif *netif);
int arp_handle_packet(arp_request_t *arp, uint16_t len, struct netif *netif);

#ifdef __cplusplus
}
#endif
#endif
