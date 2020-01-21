/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_UDP
#define _KERNEL_UDP

#include <stdint.h>

#include <onyx/network.h>
#include <onyx/semaphore.h>

typedef struct udp
{
	uint16_t source_port;
	uint16_t dest_port;
	uint16_t len;
	uint16_t checksum;
	uint8_t payload[0];
} udp_header_t;

static inline uint16_t udpsum(udp_header_t *hdr)
{
	uint32_t sum = 0;
	uint32_t ret = 0;
	uint16_t *ptr = (uint16_t*) hdr;
	for(int i = 0; i < (hdr->len * 2); i++)
	{
		sum += ptr[i];
	}
	ret = sum & 0xFFFF;
	uint32_t carry = sum - ret;
	while(carry)
	{
		ret += carry;
		carry = (ret - (ret & 0xFFFF)) >> 16;
		ret &= 0xFFFF;
	}
	return ~ret;
}

struct udp_packet
{
	struct sockaddr_in addr;
	void *payload;
	size_t size;
	struct udp_packet *next;
};

struct udp_socket
{
	struct socket socket;
	int type;
	struct sockaddr_in src_addr;
	struct sockaddr_in dest_addr;
	struct semaphore packet_semaphore;
	struct udp_packet *packet_list;
	struct spinlock packet_lock;
	struct list_head socket_list_head;
};

int udp_send_packet(char *payload, size_t payload_size, int source_port, int dest_port, 
		uint32_t srcip, uint32_t destip, struct netif *netif);
struct socket *udp_create_socket(int type);
int udp_init_netif(struct netif *netif);
void udp_handle_packet(ip_header_t *header, size_t length, struct netif *netif);

#endif
