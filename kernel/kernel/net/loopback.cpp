/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>

#include <onyx/init.h>
#include <onyx/packetbuf.h>
#include <onyx/byteswap.h>

#include <onyx/net/netif.h>
#include <onyx/net/ethernet.h>
#include <onyx/net/network.h>

packetbuf_proto *loopback_get_packetbuf_proto(netif *n)
{
	return eth_get_packetbuf_proto();
} 

int loopback_send_packet(const void *buffer, uint16_t size, netif *nif)
{
	/* This requires a terribly-spooky cast but it should be fine for now.
	 * TODO: Mark network_handle_packet's buffer as const?.
	 */
	/* TODO: Detect errors */
#if 0
	printk("send packet loopback\n");
#endif
	network_handle_packet((uint8_t *) buffer, size, nif);
	return 0;
}

void loopback_init(void)
{
	netif *n = new netif{};
	n->flags = NETIF_LINKUP | NETIF_LOOPBACK;
	n->name = "loopback";
	n->mtu = UINT16_MAX;
	n->local_ip.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	n->router_ip.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	n->sendpacket = loopback_send_packet;
	n->get_packetbuf_proto = loopback_get_packetbuf_proto;

	netif_register_if(n);
}

INIT_LEVEL_CORE_KERNEL_ENTRY(loopback_init);
