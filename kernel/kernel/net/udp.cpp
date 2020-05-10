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

	uint16_t r = __ipsum_unfolded(&__src, sizeof(srcip), 0);
	r = __ipsum_unfolded(&__dst, sizeof(dstip), r);
	r = __ipsum_unfolded(&proto, sizeof(proto), r);
	r = __ipsum_unfolded(&header->len, sizeof(header->len), r);

	r = __ipsum_unfolded(header, packet_length & 1 ? packet_length + 1 : packet_length, r);

	return ipsum_fold(r);
}

#include <onyx/clock.h>

size_t udpv4_get_packetlen(void *info, struct packetbuf_proto **next, void **next_info);

struct packetbuf_proto udpv4_proto =
{
	.name = "udp",
	.get_len = udpv4_get_packetlen
};

size_t udpv4_get_packetlen(void *info, struct packetbuf_proto **next, void **next_info)
{
	netif *n = static_cast<netif *>(info);

	(void) n;

	*next = ipv4_get_packetbuf();
	*next_info = info;

	return sizeof(udp_header_t);
}

int udp_send_packet(char *payload, size_t payload_size, in_port_t source_port,
	            in_port_t dest_port, in_addr_t srcip, in_addr_t destip,
		    	struct netif *netif)
{
	bool padded = false;

	if(payload_size & 1)
	{
		padded = true;
		payload_size++;
	}

	if(payload_size > UINT16_MAX)
		return errno = EMSGSIZE, -1;

	struct packetbuf_info buf = {0};
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

int udp_bind(sockaddr *addr, socklen_t addrlen, socket *sock)
{
	udp_socket *socket = static_cast<udp_socket *>(sock);

	return socket->bind(addr, addrlen);
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

	memcpy(&dest_addr, addr, sizeof(struct sockaddr));
	connected = true;

	return 0;
}

int udp_connect(sockaddr *addr, socklen_t addrlen, socket *sock)
{
	udp_socket *socket = static_cast<udp_socket *>(sock);
	return socket->connect(addr, addrlen);
}

ssize_t udp_socket::sendto(const void *buf, size_t len, int flags, struct sockaddr *addr,
                           socklen_t addrlen)
{
	bool not_conn = !connected;

	struct sockaddr_in *to = (struct sockaddr_in *) &dest_addr;

	struct sockaddr_in *in = (struct sockaddr_in *) addr;

	if(in && !validate_sockaddr_len_pair(addr, addrlen))
		return -EINVAL;

	if(not_conn && addr == NULL)
		return -ENOTCONN;
	else if(addr != NULL)
		to = (struct sockaddr_in *) addr;

	struct sockaddr from;
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

ssize_t udp_sendto(const void *buf, size_t len, int flags, sockaddr *addr,
	socklen_t addrlen, socket *sock)
{
	udp_socket *socket = (struct udp_socket*) sock;
	return socket->sendto(buf, len, flags, addr, addrlen);
}

/* udp_get_queued_packet - Gets either a packet that was queued on receive or waits for one */
struct udp_packet *udp_get_queued_packet(udp_socket *socket)
{
	sem_wait(&socket->packet_semaphore);
	spin_lock(&socket->packet_lock);

	struct udp_packet *packet = socket->packet_list;
	socket->packet_list = packet->next;

	spin_unlock(&socket->packet_lock);

	return packet;
}

ssize_t udp_recvfrom(void *buf, size_t len, int flags,
	struct sockaddr *src_addr, socklen_t *slen, struct socket *sock)
{
	struct udp_socket *socket = (struct udp_socket*) sock;

	bool storing_src = src_addr ? true : false;

	struct udp_packet *packet = udp_get_queued_packet(socket);

	assert(packet != NULL);
	
	ssize_t to_copy = min(len, packet->size);

	memcpy(buf, packet->payload, to_copy);

	if(storing_src)
	{
		memset(&packet->addr.sin_zero, 0, sizeof(packet->addr.sin_zero));

		if(copy_to_user(src_addr, &packet->addr, sizeof(packet->addr)) < 0)
		{
			free(packet);
			return -EFAULT;
		}

		socklen_t length = sizeof(packet->addr);
		if(copy_to_user(slen, &length, sizeof(socklen_t)) < 0)
		{
			free(packet);
			return -EFAULT;
		}
	}

	free(packet);

	return to_copy;
}

struct sock_ops udp_ops = 
{
	.listen = default_listen,
	.accept = default_accept,
	.bind = udp_bind,
	.connect = udp_connect,
	.sendto = udp_sendto,
	.recvfrom = udp_recvfrom,
};

struct socket *udp_create_socket(int type)
{
	struct udp_socket *socket = new udp_socket();
	if(!socket)
		return NULL;
	
	socket->s_ops = &udp_ops;
	
	return (struct socket*) socket;
}

int udp_init_netif(struct netif *netif)
{
	return 0;
}

void udp_append_packet(struct udp_packet *packet, struct udp_socket *socket)
{
	spin_lock(&socket->packet_lock);

	struct udp_packet **pp = &socket->packet_list;
	
	while(*pp)
		pp = &(*pp)->next;

	*pp = packet;

	spin_unlock(&socket->packet_lock);

	sem_signal(&socket->packet_semaphore);
}

bool valid_udp_packet(udp_header_t *header, size_t length)
{
	if(sizeof(udp_header_t) > length)
		return false;
	if(ntohs(header->len) > length)
		return false;

	return true;
}

void udp_handle_packet(struct ip_header *header, size_t length, struct netif *netif)
{
	udp_header_t *udp_header = (udp_header_t *) (header + 1);

	if(!valid_udp_packet(udp_header, length))
		return;

	struct sockaddr_in socket_dst;
	ipv4_to_sockaddr(header->source_ip, udp_header->source_port, socket_dst);

	struct udp_packet *packet = static_cast<udp_packet *>(zalloc(sizeof(*packet)));
	if(!packet)
	{
		printf("udp: Could not allocate packet memory\n");
		return;
	}

	size_t payload_len = ntoh16(udp_header->len) - sizeof(udp_header_t);

	packet->size = payload_len;
	packet->payload = memdup(udp_header + 1, payload_len);
	memcpy(&packet->addr, &socket_dst, sizeof(socket_dst));

	if(!packet->payload)
	{
		printf("udp: Could not allocate payload memory\n");
		free(packet);
		return;
	}

	auto socket = inet_resolve_socket<udp_socket>(header->source_ip,
                      udp_header->source_port, udp_header->dest_port, PROTOCOL_UDP,
					  netif, true);
	if(!socket)
	{
		free(packet->payload);
		free(packet);
		return;
	}

	udp_append_packet(packet, socket);

	socket_unref(socket);
}
