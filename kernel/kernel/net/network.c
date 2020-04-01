/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include <onyx/log.h>
#include <onyx/network.h>
#include <onyx/ip.h>
#include <onyx/udp.h>
#include <onyx/icmp.h>
#include <onyx/compiler.h>
#include <onyx/dns.h>
#include <onyx/file.h>
#include <onyx/ethernet.h>
#include <onyx/dpc.h>
#include <onyx/network.h>
#include <onyx/slab.h>

static const char *hostname = "";

int network_handle_packet(uint8_t *packet, uint16_t len, struct netif *netif)
{
	ethernet_header_t *hdr = (ethernet_header_t*) packet;
	
	/* Bad packet */
	if(sizeof(ethernet_header_t) >= len)
		return 0;
	
	hdr->ethertype = LITTLE_TO_BIG16(hdr->ethertype);
	if(hdr->ethertype == PROTO_IPV4)
		ipv4_handle_packet((struct ip_header*)(hdr + 1), len - sizeof(ethernet_header_t), netif);
	else if(hdr->ethertype == PROTO_ARP)
		arp_handle_packet((arp_request_t*)(hdr + 1), len - sizeof(ethernet_header_t), netif);

	return 0;
}

const char *network_gethostname()
{
	return hostname;
}

void network_sethostname(const char *name)
{
	/* TODO: Invalidate the dns cache entry of the last host name */
	if(strcmp((char*) hostname, ""))
		free((void *) hostname);
	hostname = name;
}

static slab_cache_t *network_slab;

void network_do_dispatch(void *__args)
{
	struct network_args *args = __args;
	network_handle_packet(args->buffer, args->size, args->netif);
	slab_free(network_slab, __args);
}

#ifndef NET_POOL_NUM_OBJS
#define NET_POOL_NUM_OBJS	512
#endif

void __init network_init(void)
{
	network_slab = slab_create("net", sizeof(struct network_args), 0,
			SLAB_FLAG_POOL, NULL, NULL);
	assert(network_slab != NULL);

	assert(slab_populate(network_slab, NET_POOL_NUM_OBJS) != -1);
}

void network_dispatch_recieve(uint8_t *packet, uint16_t len, struct netif *netif)
{
	struct network_args *args = slab_allocate(network_slab);
	if(!args)
	{
		ERROR("net", "Could not recieve packet: Out of memory inside IRQ\n");
		return;
	}

	args->buffer = packet;
	args->size = len;
	args->netif = netif;

	struct dpc_work work = {0};
	work.funcptr = network_do_dispatch;
	work.context = args;
	dpc_schedule_work(&work, DPC_PRIORITY_HIGH);
}
