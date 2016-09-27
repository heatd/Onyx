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

#include <kernel/arp.h> 
int send_arp_request_ipv4(char *requested_ip)
{
	arp_request_t *arp = malloc(sizeof(arp_request_t));
	if(!arp)
		return 1;
	memset(arp, 0, sizeof(arp_request_t));
	arp->htype = LITTLE_TO_BIG16(ARP_ETHERNET);
	arp->ptype = LITTLE_TO_BIG16(PROTO_IPV4); 
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
	arp->sender_proto_address[0] =  192;
	arp->sender_proto_address[1] = 168;
	arp->sender_proto_address[2] = 1;
	arp->sender_proto_address[3] = 187;
	memcpy(&arp->target_proto_address, requested_ip, ARP_PLEN_IPV4);
	int ret = eth_send_packet(&arp->target_hw_address, arp, sizeof(arp_request_t), PROTO_ARP);
//	free(arp);
	return ret;
}