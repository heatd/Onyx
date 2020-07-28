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

#include <netinet/in.h>

uint16_t udpv4_calculate_checksum(udp_header_t *header, uint32_t srcip, uint32_t dstip)
{
	uint16_t proto = IPV4_UDP << 8;
	uint16_t packet_length = ntohs(header->len);
	uint16_t __src[2];
	uint16_t __dst[2];

	memcpy(&__src, &srcip, sizeof(srcip));
	memcpy(&__dst, &dstip, sizeof(dstip));

	auto r = __ipsum_unfolded(&__src, sizeof(srcip), 0);
	r = __ipsum_unfolded(&__dst, sizeof(dstip), r);
	r = __ipsum_unfolded(&proto, sizeof(proto), r);
	r = __ipsum_unfolded(&header->len, sizeof(header->len), r);

	r = __ipsum_unfolded(header, packet_length & 1 ? packet_length + 1 : packet_length, r);

	return ipsum_fold(r);
}

#include <onyx/clock.h>

size_t udpv4_get_packetlen(void *info, packetbuf_proto **next, void **next_info);

packetbuf_proto udpv4_proto =
{
	.name = "udp",
	.get_len = udpv4_get_packetlen
};

size_t udpv4_get_packetlen(void *info, packetbuf_proto **next, void **next_info)
{
	netif *n = static_cast<netif *>(info);

	(void) n;

	*next = ipv4_get_packetbuf();
	*next_info = info;

	return sizeof(udp_header_t);
}

int udp_send_packet(char *payload, size_t payload_size, in_port_t source_port,
	            in_port_t dest_port, in_addr_t srcip, in_addr_t destip,
		    	netif *netif)
{
	bool padded = false;

	if(payload_size & 1)
	{
		padded = true;
		payload_size++;
	}

	if(payload_size > UINT16_MAX)
		return errno = EMSGSIZE, -1;

	packetbuf_info buf = {0};
	buf.length = payload_size;
	buf.packet = NULL;

	if(packetbuf_alloc(&buf, &udpv4_proto, netif) < 0)
	{
		packetbuf_free(&buf);
		return -1;
	}
	
	udp_header_t *udp_header = reinterpret_cast<udp_header_t *>(((char *) buf.packet) + packetbuf_get_off(&buf));

	memset(udp_header, 0, sizeof(udp_header_t));

	udp_header->source_port = source_port;
	udp_header->dest_port = dest_port;

	if(padded)
	{
		*((char *) buf.packet + payload_size) = 0;
		payload_size--;
	}

	udp_header->len = htons((uint16_t)(sizeof(udp_header_t) +
					  payload_size));

	memcpy(&udp_header->payload, payload, payload_size);

	udp_header->checksum = udpv4_calculate_checksum(udp_header, srcip, destip);
	int ret = ip::v4::send_packet(srcip, destip, IPV4_UDP, &buf, netif);

	packetbuf_free(&buf);

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

	memcpy(&dest_addr, addr, sizeof(sockaddr));
	connected = true;

	return 0;
}

ssize_t udp_socket::sendto(const void *buf, size_t len, int flags, sockaddr *addr,
                           socklen_t addrlen)
{
	bool not_conn = !connected;

	sockaddr_in *to = (sockaddr_in *) &dest_addr;

	sockaddr_in *in = (sockaddr_in *) addr;

	if(in && !validate_sockaddr_len_pair(addr, addrlen))
		return -EINVAL;

	if(not_conn && addr == NULL)
		return -ENOTCONN;
	else if(addr != NULL)
		to = (sockaddr_in *) addr;

	sockaddr from;
	/* TODO: This is not quite ipv6 safe */
	memcpy(&from, &src_addr, sizeof(from));
	auto fam = get_proto_fam();
	auto netif = fam->route(&from, (sockaddr *) to);

	auto &from_in = (sockaddr_in &) from;

	if(udp_send_packet((char*) buf, len, from_in.sin_port, to->sin_port,
			   from_in.sin_addr.s_addr, to->sin_addr.s_addr, 
			   netif) < 0)
	{
		return -errno;
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
