/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_NET_UDP_H
#define _ONYX_NET_UDP_H

#include <stdint.h>

#include <onyx/net/network.h>
#include <onyx/semaphore.h>
#include <onyx/net/ip.h>
#include <onyx/wait_queue.h>

typedef struct udp
{
	uint16_t source_port;
	uint16_t dest_port;
	uint16_t len;
	uint16_t checksum;
	uint8_t payload[0];
} udp_header_t;

struct udp_packet
{
	struct sockaddr_in addr;
	void *payload;
	size_t size;
	struct udp_packet *next;
};

class udp_socket : public inet_socket
{
public:
	int bind(sockaddr *addr, socklen_t len) override;
	int connect(sockaddr *addr, socklen_t len) override;
	ssize_t sendto(const void *buf, size_t len, int flags, struct sockaddr *addr,
                   socklen_t addrlen) override;
	int getsockopt(int level, int optname, void *val, socklen_t *len) override;
	int setsockopt(int level, int optname, const void *val, socklen_t len) override;
};

int udp_send_packet(char *payload, size_t payload_size, in_port_t source_port, in_port_t dest_port, 
		in_addr_t srcip, in_addr_t destip, struct netif *netif);
struct socket *udp_create_socket(int type);
int udp_init_netif(struct netif *netif);
void udp_handle_packet(struct ip_header *header, size_t length, struct netif *netif);

#endif
