/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/net/ip.h>
#include <onyx/net/udp.h>
#include <onyx/net/tcp.h>
#include <onyx/net/netif.h>
#include <onyx/net/icmp.h>
#include <onyx/net/socket_table.h>

#include <onyx/random.h>

#include <onyx/public/socket.h>

namespace ip
{

socket *choose_protocol_and_create(int type, int protocol)
{
	switch(type)
	{
		case SOCK_DGRAM:
		{
			switch(protocol)
			{
				case IPPROTO_UDP:
					return udp_create_socket(type);
				case IPPROTO_ICMP:
					return icmp::create_socket(type);
				default:
					return nullptr;
			}
		}

		case SOCK_STREAM:
		{
			case IPPROTO_TCP:
				return tcp_create_socket(type);
			default:
				return nullptr;
		}
	}
}

/* Use linux's ephemeral ports */
static constexpr in_port_t ephemeral_upper_bound = 61000;
static constexpr in_port_t ephemeral_lower_bound = 32768;

in_port_t allocate_ephemeral_port(inet_sock_address &addr,
                                  inet_socket *sock, int domain)
{
	auto sock_table = sock->proto_info->get_socket_table();

	while(true)
	{
		in_port_t port = htons(static_cast<in_port_t>(arc4random_uniform(
			 ephemeral_upper_bound - ephemeral_lower_bound)) + ephemeral_lower_bound);

		addr.port = port;

		/* We pass the same address as the dst address but in reality, dst_addr isn't checked. */
		const socket_id id{sock->proto, domain, addr, addr};
		
		const auto hash = inet_socket::make_hash_from_id(id);

		sock_table->lock(hash);

		auto sock = sock_table->get_socket(id, GET_SOCKET_CHECK_EXISTENCE | GET_SOCKET_UNLOCKED);

		if(!sock)
			return port;
		else
		{
			/* Let's try again, boys */
			sock_table->unlock(hash);
		}
	}

}

}
