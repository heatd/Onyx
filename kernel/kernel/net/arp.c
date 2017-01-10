/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/

#include <kernel/spinlock.h>
#include <kernel/arp.h>
#include <stdlib.h>
#include <kernel/compiler.h>
#include <errno.h>
#include <kernel/ip.h>
static spinlock_t arp_spl;
arp_request_t *arp_response = NULL;
static volatile int arp_response_arrived = 0;
void arp_await_response()
{
	while(1)
	{
		if(arp_response_arrived == 1)
		{
			return;
		}
	}
}
arp_request_t *reply_to_arp_request(char *source_mac)
{
	arp_request_t *arp = malloc(sizeof(arp_request_t));
	if(!arp)
		return NULL;
	memset(arp, 0, sizeof(arp_request_t));

	arp->htype = LITTLE_TO_BIG16(ARP_ETHERNET);
	arp->ptype = 0x0008;
	arp->hlen = ARP_HLEN_ETHERNET;
	arp->plen = ARP_PLEN_IPV4;
	arp->operation = LITTLE_TO_BIG16(ARP_OP_REQUEST);
	
	memcpy(&arp->sender_hw_address, &mac_address, 6);
	memcpy(&arp->target_hw_address, source_mac, 6);
	eth_send_packet((char*) &arp->target_hw_address, (char*) arp, sizeof(arp_request_t), PROTO_ARP);
	free(arp);
	return arp;
}
arp_request_t* send_arp_request_ipv4(char *requested_ip)
{
	arp_request_t *arp = malloc(sizeof(arp_request_t));
	if(!arp)
		return errno = ENOMEM, NULL;
	memset(arp, 0, sizeof(arp_request_t));
	arp->htype = LITTLE_TO_BIG16(ARP_ETHERNET);
	arp->ptype = 0x0008;
	arp->hlen = ARP_HLEN_ETHERNET;
	arp->plen = ARP_PLEN_IPV4;
	arp->operation = LITTLE_TO_BIG16(ARP_OP_REQUEST);
	
	memcpy(&arp->sender_hw_address, &mac_address, 6);
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
	memcpy(&arp->target_proto_address, requested_ip, ARP_PLEN_IPV4);
	acquire_spinlock(&arp_spl);
	int st = eth_send_packet((char*) &arp->target_hw_address, (char*) arp, sizeof(arp_request_t), PROTO_ARP);
	if(st)
		return NULL;
	arp_await_response();
	arp_response_arrived = 0;
	free(arp);
	arp_request_t *ret = malloc(sizeof(arp_request_t));
	if(!ret) return errno = ENOMEM, ret;
	memcpy(ret, arp_response, sizeof(arp_request_t));
	release_spinlock(&arp_spl);
	return ret;
}
int arp_handle_packet(arp_request_t *arp, uint16_t len)
{
	arp->operation = LITTLE_TO_BIG16(arp->operation);
	if((uint32_t) *arp->target_proto_address == ip_local_ip && arp->operation == ARP_OP_REQUEST)
	{
		// If some machine is querying our IP, respond to it
		reply_to_arp_request((char*) &arp->sender_hw_address);
		// This should do the trick, open an issue on the bug tracker if there's any problem with this
		return 0;

	}
	if(arp_response == NULL)
		arp_response = malloc(sizeof(arp_request_t));
	memcpy(arp_response, arp, len);
	arp_response_arrived = 1;
	return 0;
}