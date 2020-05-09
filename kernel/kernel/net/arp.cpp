/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Don't change the include order! Maybe TOFIX? */
#include <onyx/net/ethernet.h>
#include <onyx/net/netif.h>
#include <onyx/spinlock.h>
#include <onyx/arp.h>
#include <onyx/compiler.h>
#include <onyx/net/ip.h>
#include <onyx/log.h>
#include <onyx/byteswap.h>

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
	arp_cache *c = static_cast<arp_cache *>(zalloc(sizeof(struct arp_cache)));
	if(!c)
		return NULL;

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

int arp_handle_packet(arp_request_t *arp, uint16_t len, struct netif *netif)
{
	/* We're not interested in handling requests right now. TODO: Maybe add this? */
	if(htons(arp->operation) != ARP_OP_REPLY)
		return 0;

	in_addr_t req_ip = arp->sender_proto_address;
	struct arp_cache *arp_req = arp_find(netif, req_ip);

	/* Huh, RIP */
	if(!arp_req)
		return -ENOMEM;

	memcpy(&arp_req->mac, arp->sender_hw_address, ARP_HLEN_ETHERNET);

	arp_req->flags |= ARP_FLAG_RESOLVED;

	return 0;
}

size_t arp_get_packetlen(void *info, struct packetbuf_proto **next, void **next_info);

struct packetbuf_proto arp_proto = 
{
	.name = "arp",
	.get_len = arp_get_packetlen
};

size_t arp_get_packetlen(void *info, struct packetbuf_proto **next, void **next_info)
{
	struct netif *n = static_cast<struct netif *>(info);
	

	*next = n->get_packetbuf_proto(n);
	*next_info = info;

	return sizeof(arp_request_t);
}

int arp_submit_request(struct arp_cache *c, struct netif *netif)
{
	struct packetbuf_info bufs = {};
	bufs.packet = NULL;
	bufs.length = 0;
	
	if(packetbuf_alloc(&bufs, &arp_proto, netif) < 0)
		return -ENOMEM;

	size_t arp_header_off = packetbuf_get_off(&bufs);
	arp_request_t *arp = reinterpret_cast<arp_request_t *>(((char *) bufs.packet) + arp_header_off);
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
	arp->target_proto_address = c->ip;
	int st = eth_send_packet((char*) &arp->target_hw_address, &bufs, PROTO_ARP, netif);
	
	packetbuf_free(&bufs);


	return st;
}

int arp_resolve_in(uint32_t ip, unsigned char *mac, struct netif *netif)
{
	struct arp_cache *arp = arp_find(netif, ip);
	if(!arp)
		return -ENOMEM;

	if(arp->flags & ARP_FLAG_RESOLVED)
	{
		memcpy(mac, &arp->mac, 6);
		return 0;
	}
	else
	{
		int st = arp_submit_request(arp, netif);
		if(st < 0)
		{
			return st;
		}

		/* TODO: Timeout */
		while(!(arp->flags & ARP_FLAG_RESOLVED))
			sched_sleep_ms(10);
		
		memcpy(mac, &arp->mac, 6);
		return 0;
	}
}
