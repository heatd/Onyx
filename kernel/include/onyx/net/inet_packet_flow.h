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
#include <onyx/net/inet_route.h>

#include <netinet/in.h>

struct iflow
{
	inet_sock_address saddr;
	inet_sock_address daddr;
	netif *nif;

	const inet_route& route;

	union
	{
		uint8_t hop_limit;
		uint8_t ttl;
	};

	unsigned int df : 1;
	uint8_t protocol;
	uint8_t tos;

	constexpr iflow(const inet_route& route, uint8_t protocol, bool is_v6)
	          : nif{route.nif}, route{route}, ttl{64}, df{}, protocol{protocol}, tos{}
	{
		if(!is_v6)
		{
			daddr = inet_sock_address{route.dst_addr.in4, 0};
			saddr = inet_sock_address{route.dst_addr.in4, 0};
		}
		else
		{
			daddr = inet_sock_address{route.dst_addr.in6, 0, nif->if_id};
			saddr = inet_sock_address{route.src_addr.in6, 0, nif->if_id};
		}
	}

	constexpr iflow(const inet_route& route, const inet_sock_address& saddr,
	                const inet_sock_address& daddr, uint8_t protocol)
	          : saddr{saddr}, daddr{daddr}, nif{route.nif}, route{route},
	            ttl{64}, df{}, protocol{protocol}, tos{}
	{
	}
};

#endif
