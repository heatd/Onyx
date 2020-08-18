/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_NET_INET_ROUTE_H
#define _ONYX_NET_INET_ROUTE_H

#include <onyx/net/netif.h>
#include <onyx/net/neighbour.h>

#include <onyx/public/socket.h>
#include <netinet/in.h>

/* Internal routing table entry */
struct inet4_route
{
	in_addr_t dest;
	in_addr_t mask;
	in_addr_t gateway;
	netif *nif;
	int metric;
	unsigned short flags;
};

struct inet6_route
{
	in6_addr dest;
	in6_addr mask;
	in6_addr gateway;
	netif *nif;
	int metric;
	unsigned short flags;
};

#define INET4_ROUTE_FLAG_GATEWAY    (1 << 0)
#define INET4_ROUTE_FLAG_SCOPE_LOCAL (1 << 1)

/* Cached information of the route the packet should take from here to the dst.
 */
struct inet_route
{
	union addr
	{
		in_addr in4;
		in6_addr in6;
	};

	addr src_addr;
	addr dst_addr;

	/* Only valid if flags & INET4_ROUTE_FLAG_GATEWAY */
	addr gateway_addr;

	netif *nif;
	unsigned short flags;
	shared_ptr<neighbour> dst_hw;
};

#endif
