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
#include <onyx/arp.h>
#include <onyx/net/network.h>
#include <onyx/vm.h>
#include <onyx/crc32.h>
#include <onyx/byteswap.h>

#include <pci/pci.h>

size_t eth_get_packetlen(void *info, struct packetbuf_proto **next, void **next_info);

struct packetbuf_proto __eth_proto = 
{
	.name = "eth",
	.get_len = eth_get_packetlen
};

size_t eth_get_packetlen(void *info, struct packetbuf_proto **next, void **next_info)
{
	struct netif *n = static_cast<netif *>(info);
	
	if(n->if_proto)
	{
		*next = n->if_proto;
		*next_info = info;
	}

	return sizeof(ethernet_header_t);
}

int eth_send_packet(char *destmac, struct packetbuf_info *buf, uint16_t protocol, struct netif *netif)
{
	size_t eth_header_off = packetbuf_get_off(buf);
	auto hdr = reinterpret_cast<ethernet_header_t*>(((char *) buf->packet) + eth_header_off);

	memset(hdr, 0, sizeof(ethernet_header_t));

	hdr->ethertype = htons(protocol);
	memcpy(&hdr->mac_dest, destmac, 6);
	memcpy(&hdr->mac_source, &netif->mac_address, 6);

	int status = netif_send_packet(netif, (char*) hdr, buf->length);

	return status;
}
