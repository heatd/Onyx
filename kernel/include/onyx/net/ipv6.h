/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_NET_IPV6_H
#define _ONYX_NET_IPV6_H

#include <onyx/net/inet_sock_addr.h>
#include <onyx/net/inet_socket.h>
#include <onyx/tuple.hpp>

#include <sys/socket.h>
#include <netinet/in.h>

struct ip6hdr
{

#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int traffic_class : 4;
	unsigned int version : 4;
#else
	unsigned int version : 4;
	unsigned int traffic_class : 4;
#endif

	uint8_t flow_label[3];
	uint16_t payload_length;
	uint8_t next_header;
	uint8_t hop_limit;
	in6_addr src_addr;
	in6_addr dst_addr;
} __attribute__((packed));

namespace ip
{

namespace v6
{

	/* IPv4-mapped IPv6 addresses are special addresses recognised by a
	 * lot of hybrid dual-stack IPv4/v6 implementations. These addresses consist in an 80-bit prefix
	 * of zeros, followed by 16 bits of ones and the remaining part of the address(32-bits) is the
	 * IPv4 address.
	 */
	constexpr bool is_ipv4_mapped_addr(const sockaddr_in6 *sa)
	{
		/* First we test the first 64-bits(two 32-bit compares), then we test the 5th 16-bit word,
		 * such that we test for the 80-bits of zeros. Then we just test if the following 16-bit word
		 * is 0xffff.
		 */
		return sa->sin6_addr.s6_addr32[0] == 0 && sa->sin6_addr.s6_addr32[1] == 0
		       && sa->sin6_addr.s6_addr16[4] == 0 && sa->sin6_addr.s6_addr16[5] == 0xffff;
	}

	/* Used on IPv4-mapped IPv6 addresses */
	constexpr in_addr sa6_to_ipv4(const sockaddr_in6 *sa)
	{
		return {sa->sin6_addr.s6_addr32[3]};
	}

	inline constexpr cul::pair<inet_sock_address, int> sockaddr6_to_isa(const sockaddr_in6* sa)
	{
		if(is_ipv4_mapped_addr(sa))
			return {inet_sock_address{sa6_to_ipv4(sa), sa->sin6_port}, AF_INET};
		else
			return {inet_sock_address{*sa}, AF_INET6};
	} 

	int send_packet(const in6_addr& src, const in6_addr& dst, unsigned int type,
                     packetbuf *buf, struct netif *netif);
}

}

#endif
