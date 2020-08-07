/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/net/ip.h>

bool inet_socket::validate_sockaddr_len_pair_v6(sockaddr_in6 *addr, socklen_t len)
{
	if(len != sizeof(sockaddr_in6))
		return false;

	return addr->sin6_family == AF_INET6;
}

namespace ip
{

namespace v6
{

static constexpr tx_type ipv6_addr_to_tx_type(const in6_addr& dst)
{
	return dst.s6_addr[0] == 0xff ? tx_type::broadcast : tx_type::unicast;
}

int send_packet(const in6_addr& src, const in6_addr& dst, unsigned int type,
                     packetbuf *buf, netif *netif)
{
	const auto length = buf->length(); 
	auto hdr = reinterpret_cast<ip6hdr *>(buf->push_header(sizeof(ip6hdr)));
	
	hdr->src_addr = src;
	hdr->dst_addr = dst;
	
	for(auto &f : hdr->flow_label)
		f = 0;
	
	hdr->traffic_class = 0;
	hdr->version = 6;
	hdr->payload_length = length;
	hdr->next_header = type;

	int st = 0;

	const auto ttype = ipv6_addr_to_tx_type(dst);
	unsigned char hwaddr[6];

	if(ttype == tx_type::unicast)
	{
		/* TODO: Implement */
		memset(hwaddr, 0, sizeof(hwaddr));
	}

	if((st = netif->dll_ops->setup_header(buf, ttype, tx_protocol::ipv6, netif, hwaddr)) < 0)
		return st;
	
	return netif_send_packet(netif, buf);
}

}

}
