/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/net/ip.h>
#include <onyx/net/socket_table.h>

const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
const struct in6_addr in6addr_loopback = IN6ADDR_LOOPBACK_INIT;

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
	return dst.s6_addr[0] == 0xff ? tx_type::multicast : tx_type::unicast;
}

int send_packet(const inet_route& route, unsigned int type,
                     packetbuf *buf, struct netif *netif)
{
	const auto length = buf->length(); 
	auto hdr = reinterpret_cast<ip6hdr *>(buf->push_header(sizeof(ip6hdr)));
	
	hdr->src_addr = route.src_addr.in6;
	hdr->dst_addr = route.dst_addr.in6;
	
	for(auto &f : hdr->flow_label)
		f = 0;
	
	hdr->traffic_class = 0;
	hdr->version = 6;
	hdr->payload_length = htons(length);
	hdr->next_header = type;

	int st = 0;

	const auto ttype = ipv6_addr_to_tx_type(route.dst_addr.in6);
	const void *dst_hw = nullptr;

	if(ttype == tx_type::unicast)
	{
		dst_hw = route.dst_hw->hwaddr().data();
	}
	else if(ttype == tx_type::multicast)
	{
		/* Let the lower layer figure out the multicast address */
		dst_hw = &hdr->dst_addr;
	}

	if((st = netif->dll_ops->setup_header(buf, ttype, tx_protocol::ipv6, netif, dst_hw)) < 0)
		return st;
	
	return netif_send_packet(netif, buf);
}

int proto_family::bind_internal(sockaddr_in6 *in, inet_socket *sock)
{
	auto proto_info = sock->proto_info;
	auto sock_table = proto_info->get_socket_table();

	inet_sock_address addr{*in};
	fnv_hash_t hash = 0;
	const socket_id id(sock->proto, AF_INET6, addr, addr);

	/* Some protocols have no concept of ports, like ICMP, for example. 
	 * These are special cases that require that in->sin_port = 0 **and**
	 * we do not allocate a port, like we would for standard sin_port = 0.
	 */
	bool proto_has_no_ports = false;

	if(proto_has_no_ports && in->sin6_port != 0)
		return -EINVAL;

	if(in->sin6_port != 0 || proto_has_no_ports)
	{
		if(!proto_has_no_ports && !inet_has_permission_for_port(in->sin6_port))
			return -EPERM;

		hash = inet_socket::make_hash_from_id(id);

		sock_table->lock(hash);

		/* Check if there's any socket bound to this address yet, if we're not talking about ICMP.
		 * ICMP allows you to bind multiple sockets, as they'll all receive the same packets.
		 */
		if(!proto_has_no_ports && sock_table->get_socket(id,
		                      GET_SOCKET_CHECK_EXISTENCE | GET_SOCKET_UNLOCKED))
		{
			sock_table->unlock(hash);
			return -EADDRINUSE;
		}
	}
	else
	{
		/* Lets try to allocate a new ephemeral port for us */
		in->sin6_port = allocate_ephemeral_port(addr, sock, AF_INET6);
		hash = inet_socket::make_hash_from_id(id);
	}

	sock->src_addr = addr;

	/* Note: locks need to be held */
	bool success = sock_table->add_socket(sock, ADD_SOCKET_UNLOCKED);

	sock_table->unlock(hash);

	return success ? 0 : -ENOMEM;
}

static constexpr bool is_bind_any6(in6_addr addr)
{
	return addr == in6addr_any;
}

int proto_family::bind(sockaddr *addr, socklen_t len, inet_socket *sock)
{
	if(len != sizeof(sockaddr_in6))
		return -EINVAL;

	sockaddr_in6 *in = (sockaddr_in6 *) addr;

	int st = 0;

	if(!sock->validate_sockaddr_len_pair(addr, len))
		return -EINVAL;

	st = bind_internal(in, sock);

	if(st < 0)
		return st;
	
	sock->bound = true;
	return 0;
}

int proto_family::bind_any(inet_socket *sock)
{
	sockaddr_in6 in = {};
	in.sin6_family = AF_INET6;
	in.sin6_addr = IN6ADDR_ANY_INIT;
	in.sin6_port = 0;

	return bind((sockaddr *) &in, sizeof(sockaddr_in6), sock);
}

void proto_family::unbind(inet_socket *sock)
{
	sock->proto_info->get_socket_table()->remove_socket(sock, 0);
}

rwlock routing_table_lock;
cul::vector<shared_ptr<inet6_route>> routing_table;

expected<inet_route, int> proto_family::route(const inet_sock_address& from,
                                              const inet_sock_address& to, int domain)
{
	if(domain == AF_INET)
		return ip::v4::get_v4_proto()->route(from, to, domain);

	netif *required_netif = nullptr;
	/* If the source address specifies an interface, we need to use that one. */
	if(!is_bind_any6(from.in6))
	{
		required_netif = netif_get_from_addr(from, AF_INET6);
		if(!required_netif)
			return unexpected<int>{-ENETDOWN};
	}

	/* Else, we're searching through the routing table to find the best interface to use in order
	 * to reach our destination
	 */
	shared_ptr<inet6_route> best_route;
	int highest_metric = 0;
	auto dest = to.in6;

	rw_lock_read(&routing_table_lock);

	for(auto &r : routing_table)
	{
		/* Do a bitwise and between the destination address and the mask
		 * If the result = r.dest, we can use this interface.
		 */
#if 0
		printk("dest %x, mask %x, supposed dest %x\n", dest, r->mask, r->dest);
#endif
		if((dest & r->mask) != r->dest)
			continue;
		
		if(required_netif && r->nif != required_netif)
			continue;
#if 0
		printk("%s is good\n", r->nif->name);
		printk("is loopback set %u\n", r->nif->flags & NETIF_LOOPBACK);
#endif
	
		int mods = 0;
		if(r->flags & INET4_ROUTE_FLAG_GATEWAY)
			mods--;

		if(r->metric + mods > highest_metric)
		{
			best_route = r;
			highest_metric = r->metric;
		}
	}

	rw_unlock_read(&routing_table_lock);

	if(!best_route)
		return unexpected<int>{-ENETUNREACH};
	
	inet_route r;
	r.dst_addr.in6 = to.in6;
	r.nif = best_route->nif;
	r.src_addr.in6 = r.nif->local_ip6;
	r.flags = best_route->flags;
	r.gateway_addr.in6 = best_route->gateway;

	auto to_resolve = r.dst_addr.in6;

	if(r.flags & INET4_ROUTE_FLAG_GATEWAY)
	{
		to_resolve = r.gateway_addr.in6;
	}

#if 0
	auto res = arp_resolve_in(to_resolve, r.nif);

	if(res.has_error()) [[unlikely]]
	{
		return unexpected<int>(-ENETUNREACH);
	}

	r.dst_hw = res.value();
#endif

	return r;
}

bool add_route(inet6_route &route)
{
	rw_lock_write(&routing_table_lock);

	auto ptr = make_shared<inet6_route>();
	if(!ptr)
		return false;
	
	memcpy(ptr.get(), &route, sizeof(route));

	bool st = routing_table.push_back(ptr);

	rw_unlock_write(&routing_table_lock);

	return st;
}

static ip::v6::proto_family v6_protocol;

socket *create_socket(int type, int protocol)
{
	/* Explicitly disallow IPPROTO_ICMP on v6 sockets */
	if(protocol == IPPROTO_ICMP)
		return errno = EAFNOSUPPORT, nullptr;

	auto sock = ip::choose_protocol_and_create(type, protocol);

	if(sock)
		sock->proto_domain = &v6_protocol;

	printk("INET6 socket!\n");

	return sock;
}

}

}
