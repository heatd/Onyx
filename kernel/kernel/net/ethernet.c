/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <kernel/ethernet.h>
#include <kernel/ip.h>
#include <kernel/arp.h>
#include <kernel/network.h>
#include <kernel/vmm.h>
#include <kernel/crc32.h>

#include <drivers/pci.h>
#include <drivers/e1000.h>


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
int eth_send_packet(char *destmac, char *payload, uint16_t len, uint16_t protocol, struct netif *netif)
{
	ethernet_header_t *hdr = malloc(len + sizeof(ethernet_header_t));
	if(!hdr)
		return errno = ENOMEM, 1;
	memset(hdr, 0, sizeof(ethernet_header_t) + len);
	memcpy(&hdr->payload, payload, len);
	hdr->ethertype = LITTLE_TO_BIG16(protocol);
	memcpy(&hdr->mac_dest, destmac, 6);
	memcpy(&hdr->mac_source, &netif->mac_address, 6);
	int status = netif_send_packet(netif, (char*) hdr, len + sizeof(ethernet_header_t));
	free(hdr);
	return status;
}
