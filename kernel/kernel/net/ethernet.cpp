/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <onyx/net/ethernet.h>
#include <onyx/net/ip.h>
#include <onyx/net/arp.h>
#include <onyx/net/network.h>
#include <onyx/vm.h>
#include <onyx/crc32.h>
#include <onyx/byteswap.h>

#include <pci/pci.h>

int eth_send_packet(char *destmac, packetbuf *buf, uint16_t protocol, struct netif *netif)
{
	auto hdr = (ethernet_header_t *) buf->push_header(sizeof(ethernet_header_t));

	memset(hdr, 0, sizeof(ethernet_header_t));

	hdr->ethertype = htons(protocol);
	memcpy(&hdr->mac_dest, destmac, 6);
	memcpy(&hdr->mac_source, &netif->mac_address, 6);

	int status = netif_send_packet(netif, buf);

	return status;
}
