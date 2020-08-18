/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_NET_ICMPV6_H
#define _ONYX_NET_ICMPV6_H

#include <stdint.h>
#include <stddef.h>

#include <onyx/net/inet_route.h>

#define ICMPV6_DEST_UNREACHABLE   1
#define ICMPV6_PACKET_TOO_BIG     2
#define ICMPV6_TIME_EXCEEDED      3
#define ICMPV6_PARAMETER_PROBLEM  4
#define ICMPV6_ECHO_REQUEST       128
#define ICMPV6_ECHO_REPLY         129
#define ICMPV6_ROUTER_SOLICIT     133
#define ICMPV6_ROUTER_ADVERT      134
#define ICMPV6_NEIGHBOUR_SOLICIT  135
#define ICMPV6_NEIGHBOUR_ADVERT   136

struct icmpv6_header
{
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint32_t data;
} __attribute__((packed));

namespace icmpv6
{

struct send_data
{
	uint8_t type;
	uint8_t code;
	const inet_route& route;

	send_data(uint8_t t, uint8_t c, const inet_route& r) : type{t}, code{c}, route{r} {}
};

int send_packet(const send_data& data, cul::slice<unsigned char> packet_data);

}

#endif
