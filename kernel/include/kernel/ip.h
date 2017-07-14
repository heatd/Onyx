/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_IP_H
#define _KERNEL_IP_H

#include <stdint.h>
#include <kernel/ethernet.h>

#define IPV4_ICMP 1
#define IPV4_IGMP 2
#define IPV4_TCP 6
#define IPV4_UDP 17
#define IPV4_ENCAP 41
#define IPV4_OSPF 89
#define IPV4_SCTP 132
typedef struct
{
	unsigned int ihl : 4;
	unsigned int version : 4;
	unsigned int dscp : 6;
	unsigned int ecn : 2;
	uint16_t total_len;
	uint16_t identification;
	uint16_t frag_off__flags;
	uint8_t ttl;
	uint8_t proto;
	uint16_t header_checksum;
	uint32_t source_ip;
	uint32_t dest_ip;
	char payload[0];
	char options[0];
} __attribute__((packed)) ip_header_t;

static inline uint16_t ipsum(ip_header_t *hdr)
{
	uint32_t sum = 0;
	uint32_t ret = 0;
	uint16_t *ptr = (uint16_t*) hdr;
	for(int i = 0; i < (hdr->ihl * 2); i++)
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
static inline uint16_t internetchksum(void *addr, size_t bytes)
{
	uint32_t sum = 0;
	uint32_t ret = 0;
	uint16_t *ptr = (uint16_t*) addr;
	size_t words = bytes / 2;
	for(size_t i = 0; i < words; i++)
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
extern uint32_t ip_local_ip;
extern uint32_t ip_router_ip;
int send_ipv4_packet(uint32_t senderip, uint32_t destip, unsigned int type, char *payload, size_t payload_size);
void ip_set_local_ip(uint32_t lip);
void ip_set_router_ip(uint32_t rout_ip);
#endif
