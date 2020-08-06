/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_NET_INET_SOCK_ADDR_H
#define _ONYX_NET_INET_SOCK_ADDR_H

#include <sys/socket.h>

#include <netinet/in.h>

constexpr bool operator==(const in_addr& lhs, const in_addr& rhs)
{
	return lhs.s_addr == rhs.s_addr;
} 

constexpr bool operator==(const in6_addr& lhs, const in6_addr& rhs)
{
	for(int i = 0; i < 4; i++)
	{
		if(lhs.s6_addr32[i] != rhs.s6_addr32[i])
			return false;
	}

	return true;
}

struct inet_sock_address
{
	/* We keep two addresses here because I'd rather waste 4 bytes per inet socket than
	 * have "shameful" undefined behavior on compilers that != G++(and possibly clang).
	 * TL;DR we avoid the union here because union type punning is outlawed in C++ and we
	 * might trigger that.
	 */
	in_addr in4;
	in6_addr in6;
	in_port_t port;

	inet_sock_address() = default;
	explicit constexpr inet_sock_address(const sockaddr_in& sa) : in4{sa.sin_addr},
                                                                  in6{}, port{sa.sin_port}
	{}

	explicit constexpr inet_sock_address(const sockaddr_in6& sa) : in4{},
	                                                               in6{sa.sin6_addr}, port{sa.sin6_port}
	{}

	explicit constexpr inet_sock_address(const in_addr& in4, in_port_t port) : in4{in4}, in6{}, port{port}
	{}

	explicit constexpr inet_sock_address(const in6_addr& in6, in_port_t port) : in4{}, in6{in6}, port{port}
	{}

	constexpr bool equals(const inet_sock_address& rhs, bool ipv4_mode) const
	{
		if(port != rhs.port)
			return false;

		if(ipv4_mode)
		{
			return in4 == rhs.in4;
		}
		else
			return in6 == rhs.in6;
	}
};

#endif
