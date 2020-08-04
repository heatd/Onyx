/*
* Copyright (c) 2016-2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_NET_ICMP_H
#define _ONYX_NET_ICMP_H

#include <stdint.h>

#include <onyx/net/netif.h>
#include <onyx/net/ip.h>

#define ICMP_TYPE_ECHO_REPLY             0
#define ICMP_TYPE_DEST_UNREACHABLE       3
#define ICMP_TYPE_SOURCE_QUENCH          4
#define ICMP_TYPE_REDIRECT_MSG           5
#define ICMP_TYPE_ECHO_REQUEST           8
#define ICMP_TYPE_ROUTER_AD              9
#define ICMP_TYPE_ROUTER_SOLICIT         10
#define ICMP_TYPE_TIME_EXCEEDED          11
#define ICMP_TYPE_BAD_IP_HEADER          12
#define ICMP_TYPE_TIMESTAMP              13
#define ICMP_TYPE_TIMESTAMP_REPLY        14
#define ICMP_TYPE_INFO_REQUEST           15
#define ICMP_TYPE_INFO_REPLY             16
#define ICMP_TYPE_ADDRESS_MASK_REQ       17
#define ICMP_TYPE_ADDRESS_MASK_REPLY     18

/* For ICMP_TYPE_DEST_UNREACHABLE */
#define ICMP_CODE_NET_UNREACHABLE         0
#define ICMP_CODE_HOST_UNREACHABLE        1
#define ICMP_CODE_PROTO_UNREACHABLE       2
#define ICMP_CODE_PORT_UNREACHABLE        3
#define ICMP_CODE_FRAGMENTATION_REQUIRED  4
#define ICMP_CODE_SOURCE_ROUTE_FAILED     5

namespace icmp
{

struct icmp_header
{
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint32_t rest;
	union
	{
		/* ICMP destination unreachable packets contain the original
	     * IP header + 8 bytes of the original datagram.
	     */
		struct
		{
			struct ip_header header;
			unsigned char original_dgram[8];
		} dest_unreach;

		struct
		{
			uint8_t data[0];
		} echo;
	};
} __attribute__((packed));


struct dst_unreachable_info
{
	uint8_t code;
	uint16_t next_hop_mtu;
	const unsigned char *dgram;
	const ip_header *iphdr;

	dst_unreachable_info() {}
	dst_unreachable_info(uint8_t code, uint16_t next_hop_mtu,
	                    const unsigned char *dgram, const ip_header *iphdr) : code{code},
						next_hop_mtu{next_hop_mtu}, dgram{dgram}, iphdr{iphdr}
	{}
};


static constexpr unsigned int min_icmp_size()
{
	return 8;
}

void handle_packet(struct ip_header *header, uint16_t length, netif *nif);

int send_dst_unreachable(const dst_unreachable_info& info, netif *nif);

}

#endif
