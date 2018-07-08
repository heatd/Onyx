/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Don't change the include order! Maybe TOFIX?*/
#include <onyx/ethernet.h>
#include <onyx/netif.h>
#include <onyx/spinlock.h>
#include <onyx/arp.h>
#include <onyx/compiler.h>
#include <onyx/ip.h>
#include <onyx/log.h>

static volatile int arp_response_arrived = 0;
int arp_hash(uint32_t ip)
{
	return ip % 255;
}
struct arp_cache *arp_get(struct arp_hashtable *table, int hash, uint32_t ip)
{
	if(!table->entries[hash])
		return NULL;
	struct arp_cache *c = table->entries[hash];
	while(c)
	{
		if(c->ip == ip)
			return c;
		c = c->next;
	}
	return NULL;
}
struct arp_cache *arp_create(struct arp_hashtable *table, int hash, uint32_t ip)
{
	struct arp_cache *c = malloc(sizeof(struct arp_cache));
	if(!c)
		return NULL;
	memset(c, 0, sizeof(struct arp_cache));
	if(!table->entries[hash])
	{
		c->ip = ip;
		table->entries[hash] = c;
	}
	else
	{
		struct arp_cache *p = table->entries[hash];
		while(p->next) p = p->next;
		p->next = c;
	}
	return c;
}
struct arp_cache *arp_find(struct netif *netif, uint32_t ip)
{
	spin_lock(&netif->hashtable_spinlock);
	struct arp_hashtable *table = &netif->arp_hashtable;
	int hash = arp_hash(ip);
	struct arp_cache *arp = arp_get(table, hash, ip);
	if(!arp)
		arp = arp_create(table, hash, ip);
	spin_unlock(&netif->hashtable_spinlock);
	return arp;
}
int arp_submit_request(struct arp_cache *c, struct netif *netif)
{
	arp_request_t *arp = malloc(sizeof(arp_request_t));
	if(!arp)
		return errno = ENOMEM, -1;
	memset(arp, 0, sizeof(arp_request_t));
	arp->htype = LITTLE_TO_BIG16(ARP_ETHERNET);
	arp->ptype = 0x0008;
	arp->hlen = ARP_HLEN_ETHERNET;
	arp->plen = ARP_PLEN_IPV4;
	arp->operation = LITTLE_TO_BIG16(ARP_OP_REQUEST);
	
	memcpy(&arp->sender_hw_address, &netif->mac_address, 6);
	arp->target_hw_address[0] = 0xFF;
	arp->target_hw_address[1] = 0xFF;
	arp->target_hw_address[2] = 0xFF;
	arp->target_hw_address[3] = 0xFF;
	arp->target_hw_address[4] = 0xFF;
	arp->target_hw_address[5] = 0xFF;
	arp->sender_proto_address[0] =  0;
	arp->sender_proto_address[1] = 0;
	arp->sender_proto_address[2] = 0;
	arp->sender_proto_address[3] = 0;
	memcpy(&arp->target_proto_address, &c->ip, ARP_PLEN_IPV4);
	int st = eth_send_packet((char*) &arp->target_hw_address, (char*) arp, sizeof(arp_request_t), PROTO_ARP, netif);
	if(st)
		return -1;
	while(1);
}
int arp_resolve_in(uint32_t ip, unsigned char *mac, struct netif *netif)
{
	struct arp_cache *arp = arp_find(netif, ip);
	if(!arp)
		return -1;
	if(arp->flags & ARP_FLAG_RESOLVED)
	{
		memcpy(mac, &arp->mac, 6);
		return 0;
	}
	else
	{
		return arp_submit_request(arp, netif);
	}
}
