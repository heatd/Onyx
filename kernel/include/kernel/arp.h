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

#ifndef _ARP_H
#define _ARP_H

#include <stdint.h>

#include <kernel/ethernet.h>

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
	uint8_t sender_proto_address[4];
	uint8_t target_hw_address[6];
	uint8_t target_proto_address[4];

} __attribute__((packed)) arp_request_t;

arp_request_t* send_arp_request_ipv4(char *requested_ip);
int arp_handle_packet(arp_request_t *arp, uint16_t len);
#endif