/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <onyx/ethernet.h>
#include <onyx/ip.h>
#include <onyx/arp.h>
#include <onyx/network.h>
#include <onyx/vm.h>
#include <onyx/crc32.h>

#include <pci/pci.h>
#include <drivers/e1000.h>

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
