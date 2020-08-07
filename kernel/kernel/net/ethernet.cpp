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

eth_dll_ops eth_ops;

static const uint16_t eth_proto_table[] =
{
	PROTO_IPV4,
	PROTO_IPV6,
	PROTO_ARP
};

auto tx_proto_to_eth_proto(tx_protocol proto)
{
	return eth_proto_table[(int) proto];
}

int eth_dll_ops::setup_header(packetbuf *buf, tx_type type, tx_protocol proto, netif *nif, const void *dst_hw)
{
	auto hdr = (struct eth_header *) buf->push_header(sizeof(struct eth_header));

	memset(hdr, 0, sizeof(struct eth_header));

	hdr->ethertype = htons(tx_proto_to_eth_proto(proto));
	if(type != tx_type::broadcast)
		memcpy(&hdr->mac_dest, dst_hw, ETH_ALEN);
	else
		memset(hdr->mac_dest, 0xff, ETH_ALEN);

	memcpy(&hdr->mac_source, &nif->mac_address, ETH_ALEN);

	return 0;
}
