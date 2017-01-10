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

#include <stdlib.h>
#include <string.h>

#include <kernel/ethernet.h>
#include <kernel/ip.h>
#include <kernel/arp.h>
#include <kernel/network.h>
#include <kernel/vmm.h>
#include <kernel/crc32.h>

#include <drivers/pci.h>
#include <drivers/e1000.h>

char mac_address[6] = {0};
char router_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

uint8_t *packet = NULL;
uint16_t packet_len = 0;
void eth_set_packet_buf(uint8_t *buf)
{
	packet = buf;
}
void eth_set_packet_len(uint16_t len)
{
	packet_len = len;
}
static device_send_packet dev_send_packet;
void eth_set_dev_send_packet(device_send_packet p)
{
	dev_send_packet = p;
}
int eth_send_packet(char *destmac, char *payload, uint16_t len, uint16_t protocol)
{
	ethernet_header_t *hdr = malloc(len + sizeof(ethernet_header_t));
	if(!hdr)
		return 1;
	memset(hdr, 0, sizeof(ethernet_header_t) + len);
	memcpy(&hdr->payload, payload, len);
	hdr->ethertype = LITTLE_TO_BIG16(protocol);
	memcpy(&hdr->mac_dest, destmac, 6);
	memcpy(&hdr->mac_source, &mac_address, 6);
	dev_send_packet((char*)hdr, len + sizeof(ethernet_header_t));
	free(hdr);
	return 0;
}
int ethernet_handle_packet(uint8_t *packet, uint16_t len)
{
	ethernet_header_t *hdr = (ethernet_header_t*) (packet + PHYS_BASE);
	hdr->ethertype = LITTLE_TO_BIG16(hdr->ethertype);
	if(hdr->ethertype == PROTO_IPV4)
		network_handle_packet((ip_header_t*)(hdr+1), len - sizeof(ethernet_header_t));
	else if(hdr->ethertype == PROTO_ARP)
		arp_handle_packet((arp_request_t*)(hdr+1), len - sizeof(ethernet_header_t));

	return 0;
}
void eth_set_router_mac(char* mac)
{
	memcpy(&router_mac, mac, 6);
}
