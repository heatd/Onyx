/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include <kernel/network.h>
#include <kernel/ip.h>
#include <kernel/udp.h>
#include <kernel/icmp.h>
#include <kernel/compiler.h>
#include <kernel/dns.h>
#include <kernel/file.h>
#include <kernel/ethernet.h>


static const char *hostname = "";

int network_handle_packet(uint8_t *packet, uint16_t len, struct netif *netif)
{
	ethernet_header_t *hdr = (ethernet_header_t*) packet;
	hdr->ethertype = LITTLE_TO_BIG16(hdr->ethertype);
	if(hdr->ethertype == PROTO_IPV4)
		//ipv4_handle_packet((ip_header_t*)(hdr+1), len - sizeof(ethernet_header_t), netif);
	printf("Hi dad\n");
	/*else if(hdr->ethertype == PROTO_ARP)
		arp_handle_packet((arp_request_t*)(hdr+1), len - sizeof(ethernet_header_t));*/
	return 0;
}

const char *network_gethostname()
{
	return hostname;
}

void network_sethostname(const char *name)
{
	/* TODO: Invalidate the dns cache entry of the last host name */
	if(strcmp((char*) hostname, ""))
		free((void *) hostname);
	dns_fill_hashtable(dns_hash_string(name), name, 0x7F00001);
	hostname = name;
}

int check_af_support(int domain)
{
	switch(domain)
	{
		case AF_INET:
			return 0;
		default:
			return -1;
	}
}

int net_check_type_support(int type)
{
	switch(type)
	{
		case SOCK_DGRAM:
		case SOCK_RAW:
			return 0;
		default:
			return -1;
	}
}

int net_autodetect_protocol(int type, int domain)
{
	switch(type)
	{
		case SOCK_DGRAM:
			return PROTOCOL_UDP;
		case SOCK_RAW:
			return domain == AF_INET ? PROTOCOL_IPV4 : PROTOCOL_IPV6;
		case SOCK_STREAM:
			return PROTOCOL_TCP;
	}
	return -1;
}

socket_t *socket_create(int domain, int type, int protocol)
{
	switch(domain)
	{
		case AF_INET:
			return ipv4_create_socket(type, protocol);
		default:
			return errno = EAFNOSUPPORT, NULL;
	}
}

int sys_socket(int domain, int type, int protocol)
{
	int dflags;
	dflags = O_RDWR;
	if(check_af_support(domain) < 0)
		return -EAFNOSUPPORT;
	if(net_check_type_support(type) < 0)
		return -EINVAL;

	if(protocol == 0)
	{
		/* If protocol == 0, auto-detect the proto */
		if((protocol = net_autodetect_protocol(type, domain)) < 0)
			return -EINVAL;
	}

	/* Create the socket */
	socket_t *socket = socket_create(domain, type, protocol);
	if(!socket)
	{
		return -errno;
	}
	/* Open a file descriptor with the socket vnode */
	int fd = open_with_vnode((vfsnode_t*) socket, dflags);
	/* If we failed, close the socket and return */
	if(fd < 0)
		close_vfs((vfsnode_t*) socket);
	return fd;
}
