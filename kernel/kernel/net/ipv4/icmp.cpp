/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <onyx/net/network.h>
#include <onyx/net/icmp.h>
#include <onyx/net/ip.h>
#include <onyx/packetbuf.h>
#include <onyx/memory.hpp>
#include <onyx/byteswap.h>

#define ICMP_PACKETBUF_HEADER_SPACE  (PACKET_MAX_HEAD_LENGTH + sizeof(ip_header) + sizeof(icmp::icmp_header))

namespace icmp
{

unique_ptr<packetbuf> allocate_icmp_response_packet(unsigned int extra_size = 0)
{
	auto buf = make_unique<packetbuf>();
	if(!buf)
		return nullptr;
	
	if(!buf->allocate_space(ICMP_PACKETBUF_HEADER_SPACE + extra_size))
		return nullptr;
	
	buf->reserve_headers(ICMP_PACKETBUF_HEADER_SPACE);
	
	return buf;
}

void send_echo_reply(ip_header *iphdr, icmp_header *icmphdr, uint16_t length, netif *nif)
{
	in_addr dst;
	dst.s_addr = iphdr->source_ip;
	auto src = nif->local_ip.sin_addr;

	auto data_length = length - min_icmp_size();

	auto buf = allocate_icmp_response_packet(data_length);
	if(!buf)
		return;
	
	auto response_icmp = (icmp_header *) buf->push_header(min_icmp_size());

	response_icmp->type = ICMP_TYPE_ECHO_REPLY;
	response_icmp->code = 0;
	response_icmp->rest = icmphdr->rest;
	memcpy(buf->put(data_length), &icmphdr->echo.data, data_length);
	response_icmp->checksum = ipsum(response_icmp, length);

	inet_sock_address from{src, 0};
	inet_sock_address to{dst, 0};

	auto res = ip::v4::get_v4_proto()->route(from, to, AF_INET);

	if(res.has_error())
		return;

	ip::v4::send_packet(res.value(), IPV4_ICMP, buf.get(), nif);
}

int send_dst_unreachable(const dst_unreachable_info& info, netif *nif)
{
	in_addr dst;
	dst.s_addr = info.iphdr->source_ip;
	auto src = nif->local_ip.sin_addr;

	auto buf = allocate_icmp_response_packet();
	if(!buf)
		return -ENOMEM;
	
	auto response_icmp = (icmp_header *) buf->push_header(sizeof(icmp_header));

	response_icmp->type = ICMP_TYPE_DEST_UNREACHABLE;
	response_icmp->code = info.code;
	
	if(info.code == ICMP_CODE_FRAGMENTATION_REQUIRED)
		response_icmp->rest = htonl(info.next_hop_mtu << 16);
	else
		response_icmp->rest = 0;

	memcpy(&response_icmp->dest_unreach.header, info.iphdr, sizeof(ip_header));
	memcpy(&response_icmp->dest_unreach.original_dgram, info.dgram, 8);
	response_icmp->checksum = ipsum(response_icmp, sizeof(icmp_header));

	inet_sock_address from{src, 0};
	inet_sock_address to{dst, 0};

	auto res = ip::v4::get_v4_proto()->route(from, to, AF_INET);

	if(res.has_error())
		return res.error();

	return ip::v4::send_packet(res.value(), IPV4_ICMP, buf.get(), nif);
}

void handle_packet(struct ip_header *iphdr, uint16_t length, netif *nif)
{
	if(length < min_icmp_size())
		return;

	auto header = (icmp_header *) ((unsigned char *) iphdr + ip_header_length(iphdr));
	auto header_length = length;

	switch(header->type)
	{
		case ICMP_TYPE_ECHO_REQUEST:
			send_echo_reply(iphdr, header, header_length, nif);
			break;
	}
}

}
