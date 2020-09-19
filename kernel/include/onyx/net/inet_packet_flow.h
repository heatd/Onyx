/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_NET_INET_PACKET_FLOW_H
#define _ONYX_NET_INET_PACKET_FLOW_H

#include <onyx/net/inet_sock_addr.h>
#include <onyx/net/netif.h>
#include <onyx/public/socket.h>

#include <netinet/in.h>

struct iflow
{
	inet_sock_address saddr;
	inet_sock_address daddr;
	netif *nif;

	union
	{
		uint8_t hop_limit;
		uint8_t ttl;
	};

	unsigned int df : 1;
	uint8_t protocol;
	uint8_t tos;
};

#endif
