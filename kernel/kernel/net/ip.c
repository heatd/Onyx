/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <netinet/in.h>

#include <sys/socket.h>

#include <kernel/ip.h>
#include <kernel/ethernet.h>
#include <kernel/netif.h>
#include <kernel/network.h>
#include <kernel/udp.h>
#include <kernel/arp.h>

int send_ipv4_packet(uint32_t senderip, uint32_t destip, unsigned int type, char *payload, size_t payload_size, struct netif *netif)
{
	ip_header_t *ip_header = malloc(sizeof(ip_header_t) + payload_size);
	if(!ip_header)
		return errno = ENOMEM, 1;
	memset(ip_header, 0, sizeof(ip_header_t) + payload_size);
	ip_header->source_ip = LITTLE_TO_BIG32(senderip);
	ip_header->dest_ip = LITTLE_TO_BIG32(destip);
	ip_header->proto = type;
	ip_header->frag_off__flags =  LITTLE_TO_BIG16(2 & 0x7);
	ip_header->ttl = 64;
	ip_header->total_len = LITTLE_TO_BIG16((sizeof(ip_header_t) + payload_size));
	ip_header->version = 4;
	ip_header->ihl = 5;
	ip_header->header_checksum = ipsum(ip_header);
	memcpy(&ip_header->payload, payload, payload_size);

	unsigned char destmac[6] = {0};
	if(destip == INADDR_BROADCAST)
	{
		/* INADDR_BROADCAST packets are sent to mac address ff:ff:ff:ff:ff:ff */
		memset(&destmac, 0xFF, 6);
	}
	else if(destip == INADDR_LOOPBACK)
	{
		/* INADDR_LOOPBACK packets are sent to the local NIC's mac */
		memcpy(&destmac, netif->router_mac, 6);
	}
	else
	{
		/* Else, we need to send it to the router, so get the router's mac address */
		struct sockaddr_in *in = (struct sockaddr_in*) &netif->router_ip;
		if(arp_resolve_in(in->sin_addr.s_addr, destmac, netif) < 0)
			return errno = ENETUNREACH, -1;
	}

	eth_send_packet((char*) &destmac, (char*) ip_header, sizeof(ip_header_t) + payload_size, 
		PROTO_IPV4, netif);
	free(ip_header);
	return 0;
}
struct sock *ipv4_create_socket(int type, int protocol)
{
	switch(type)
	{
		case SOCK_DGRAM:
		{
			switch(protocol)
			{
				case PROTOCOL_UDP:
					return udp_create_socket(type);
			}
		}
	}
	return NULL;
}
