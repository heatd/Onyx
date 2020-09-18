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

int loopback_send_packet(packetbuf *buf, netif *nif)
{
	/* TODO: Detect errors */
#if 0
	printk("send packet loopback\n");
#endif

	auto new_buf = make_refc<packetbuf>();
	if(!new_buf)
		return -ENOMEM;
	
	if(!new_buf->allocate_space(buf->length()))
		return -ENOMEM;
	
	memcpy(new_buf->put(buf->length()), buf->data, buf->length());
	nif->dll_ops->rx_packet(nif, new_buf.get());
	return 0;
}

void loopback_init(void)
{
	netif *n = new netif{};
	n->flags = NETIF_LINKUP | NETIF_LOOPBACK;
	n->name = "loopback";
	n->mtu = UINT16_MAX;
	n->local_ip.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	n->sendpacket = loopback_send_packet;
	n->dll_ops = &eth_ops;

	netif_register_if(n);

	if_inet6_addr addr;
	addr.address = in6addr_loopback;
	addr.flags = INET6_ADDR_GLOBAL;
	addr.prefix_len = 0;

	assert(netif_add_v6_address(n, addr) == 0);
}

INIT_LEVEL_CORE_KERNEL_ENTRY(loopback_init);
