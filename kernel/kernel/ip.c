/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <kernel/ip.h>
#include <kernel/ethernet.h>

uint32_t ip_local_ip = 0;
uint32_t ip_router_ip = 0;

int send_ipv4_packet(uint32_t senderip, uint32_t destip, unsigned int type, char *payload, size_t payload_size)
{
	ip_header_t *ip_header = malloc(sizeof(ip_header_t) + payload_size);
	if(!ip_header)
		return errno = ENOMEM, 1;
	memset(ip_header, 0, sizeof(ip_header_t) + payload_size);
	ip_header->source_ip = LITTLE_TO_BIG32(senderip);
	ip_header->dest_ip = LITTLE_TO_BIG32(destip);
	ip_header->proto = type;
	ip_header->frag_off__flags =  LITTLE_TO_BIG16(2 & 0x7);
	ip_header->ttl = 0xFF;
	ip_header->total_len = LITTLE_TO_BIG16(sizeof(ip_header_t) + payload_size);
	ip_header->version = 4;
	ip_header->ihl = 5;
	ip_header->header_checksum = ipsum(ip_header);
	memcpy(&ip_header->payload, payload, payload_size);
	eth_send_packet(&router_mac, (char*) ip_header, sizeof(ip_header_t) + payload_size, PROTO_IPV4);
	free(ip_header);
	return 0;
}
void ip_set_local_ip(uint32_t lip)
{
	ip_local_ip = lip;
}
void ip_set_router_ip(uint32_t rout_ip)
{
	ip_router_ip = rout_ip;
}