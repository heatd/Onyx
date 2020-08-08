/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <endian.h>

#include <onyx/dev.h>
#include <onyx/net/ip.h>
#include <onyx/net/udp.h>
#include <onyx/net/netif.h>
#include <onyx/compiler.h>
#include <onyx/utils.h>
#include <onyx/byteswap.h>
#include <onyx/packetbuf.h>
#include <onyx/memory.hpp>
#include <onyx/net/icmp.h>

#include <netinet/in.h>

uint16_t udpv4_calculate_checksum(udp_header_t *header, uint32_t srcip, uint32_t dstip,
                                  bool do_rest_of_packet = true)
{
	uint16_t proto = IPV4_UDP << 8;
	uint16_t packet_length = htons(header->len);
	uint16_t __src[2];
	uint16_t __dst[2];

	memcpy(&__src, &srcip, sizeof(srcip));
	memcpy(&__dst, &dstip, sizeof(dstip));

	auto r = __ipsum_unfolded(&__src, sizeof(srcip), 0);
	r = __ipsum_unfolded(&__dst, sizeof(dstip), r);
	r = __ipsum_unfolded(&proto, sizeof(proto), r);
	r = __ipsum_unfolded(&header->len, sizeof(header->len), r);

	if(do_rest_of_packet)
		r = __ipsum_unfolded(header, packet_length, r);

	return ipsum_fold(r);
}

#include <onyx/clock.h>

int udp_socket::send_packet(char *payload, size_t payload_size, in_port_t source_port,
	            in_port_t dest_port, inet_route& route)
{
	auto netif = route.nif;
	auto srcip = route.src_addr.in4.s_addr;
	auto destip = route.dst_addr.in4.s_addr;

	if(payload_size > UINT16_MAX)
		return -EMSGSIZE;

	unique_ptr b = make_unique<packetbuf>();
	if(!b)
		return -ENOMEM;

	if(!b->allocate_space(payload_size + get_headers_len() + sizeof(udp_header_t) + PACKET_MAX_HEAD_LENGTH))
		return -ENOMEM;

	b->reserve_headers(get_headers_len() + sizeof(udp_header_t) + PACKET_MAX_HEAD_LENGTH);

	udp_header_t *udp_header = (udp_header_t *) b->push_header(sizeof(udp_header_t));

	memset(udp_header, 0, sizeof(udp_header_t));

	b->transport_header = (unsigned char *) udp_header;

	udp_header->source_port = source_port;
	udp_header->dest_port = dest_port;

	udp_header->len = htons((uint16_t)(sizeof(udp_header_t) + payload_size));
	
	auto ptr = b->put((unsigned int) payload_size);

	if(copy_from_user(ptr, payload, payload_size) < 0)
		return -EFAULT;

	if(netif->flags & NETIF_SUPPORTS_CSUM_OFFLOAD && !needs_fragmenting(netif, b.get()))
	{
		/* Don't supply the 1's complement of the checksum, since the network stack expects a partial sum */
		udp_header->checksum = ~udpv4_calculate_checksum(udp_header, srcip, destip, false);
		b->csum_offset = &udp_header->checksum;
		b->csum_start = (unsigned char *) udp_header;
		b->needs_csum = 1;
	}
	else
		udp_header->checksum = udpv4_calculate_checksum(udp_header, srcip, destip);

	int ret = ip::v4::send_packet(route, IPV4_UDP, b.get(), netif);

	return ret;
}

int udp_socket::bind(sockaddr *addr, socklen_t len)
{
	auto fam = get_proto_fam();
	return fam->bind(addr, len, this);
}

int udp_socket::connect(sockaddr *addr, socklen_t len)
{
	if(!validate_sockaddr_len_pair(addr, len))
		return -EINVAL;

	if(!bound)
	{
		auto fam = get_proto_fam();
		int st = fam->bind_any(this);
		if(st < 0)
			return st;
	}

	auto res = sockaddr_to_isa(addr);
	dest_addr = res.first;
	//printk("udp: Connected to address %x\n", dest_addr.in4.s_addr);
	connected = true;
	
	auto route_result = get_proto_fam()->route(src_addr, dest_addr, domain);
	
	/* If we've got an error, ignore it. Is this correct/sane behavior? */
	if(route_result.has_error())
		return 0;

	route_cache = route_result.value();
	route_cache_valid = 1;

	return 0;
}

ssize_t udp_socket::sendto(const void *buf, size_t len, int flags, sockaddr *addr,
                           socklen_t addrlen)
{
	if(addr && !validate_sockaddr_len_pair(addr, addrlen))
		return -EINVAL;

	inet_sock_address dest = dest_addr;
	int our_domain = domain;

	if(addr)
	{
		auto res = sockaddr_to_isa(addr);
		dest = res.first;
		our_domain = res.second;
	}

	if(!connected && addr == NULL)
		return -ENOTCONN;

	inet_route route;
	
	if(connected)
	{
		route = route_cache;
		assert(route_cache_valid == 1);
	}
	else
	{
		auto fam = get_proto_fam();
		auto result = fam->route(src_addr, dest, our_domain);
		if(result.has_error())
			return result.error();

		route = result.value();
	}

	/* TODO: Connect ipv6 support up */
	if(int st = send_packet((char*) buf, len, src_addr.port, dest.port,
			   route); st < 0)
	{
		return st;
	}

	return len;
}

socket *udp_create_socket(int type)
{
	return new udp_socket;
}

int udp_init_netif(netif *netif)
{
	return 0;
}

bool valid_udp_packet(udp_header_t *header, size_t length)
{
	if(sizeof(udp_header_t) > length)
		return false;
	if(ntohs(header->len) > length)
		return false;

	return true;
}

void udp_handle_packet(ip_header *header, size_t length, netif *netif)
{
	udp_header_t *udp_header = (udp_header_t *) (header + 1);

	if(!valid_udp_packet(udp_header, length))
		return;

	sockaddr_in socket_dst;
	ipv4_to_sockaddr(header->source_ip, udp_header->source_port, socket_dst);

	auto socket = inet_resolve_socket<udp_socket>(header->source_ip,
                      udp_header->source_port, udp_header->dest_port, IPPROTO_UDP,
					  netif, true);
	if(!socket)
	{
		icmp::dst_unreachable_info dst_un{ICMP_CODE_PORT_UNREACHABLE, 0,
		                (const unsigned char *) udp_header, header};
		icmp::send_dst_unreachable(dst_un, netif);
		return;
	}

	size_t payload_len = ntoh16(udp_header->len) - sizeof(udp_header_t);

	recv_packet *p = new recv_packet();
	if(!p)
	{
		printf("udp: Could not allocate packet memory\n");
		goto out;
	}

	p->size = payload_len;
	p->payload = memdup(udp_header + 1, payload_len);

	if(!p->payload)
	{
		printf("udp: Could not allocate payload memory\n");
		delete p;
		goto out;
	}

	memcpy(&p->src_addr, &socket_dst, sizeof(socket_dst));
	p->addr_len = sizeof(sockaddr_in);
	
	socket->in_band_queue.add_packet(p);

out:
	socket->unref();
}

int udp_socket::getsockopt(int level, int optname, void *val, socklen_t *len)
{
	if(is_inet_level(level))
		return getsockopt_inet(level, optname, val, len);
	if(level == SOL_SOCKET)
		return getsockopt_socket_level(optname, val, len);
	
	return -ENOPROTOOPT;
}

int udp_socket::setsockopt(int level, int optname, const void *val, socklen_t len)
{
	if(is_inet_level(level))
		return setsockopt_inet(level, optname, val, len);
	if(level == SOL_SOCKET)
		return setsockopt_socket_level(optname, val, len);
	
	return -ENOPROTOOPT;
}
