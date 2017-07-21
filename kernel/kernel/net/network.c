/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
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


static const char *hostname = "";

void network_handle_packet(ip_header_t *hdr, uint16_t len)
{
	/*hdr->source_ip = LITTLE_TO_BIG32(hdr->source_ip);
	int dest_port = 0;
	int protocol_len = 0;
	switch(hdr->proto)
	{
		case IPV4_UDP:
		{
			udp_header_t *udp_packet = (udp_header_t*)&hdr->payload;
			udp_packet->dest_port = LITTLE_TO_BIG16(udp_packet->dest_port);
			dest_port = udp_packet->dest_port;
			udp_packet->len = LITTLE_TO_BIG16(udp_packet->len);
			protocol_len = udp_packet->len;
			break;
		}
		case IPV4_ICMP:
			break;
		default:
			return;
	}*/
	
	/*for(int i = 0; i < MAX_NETWORK_CONNECTIONS; i++)
	{
		if(sock_table[i] == NULL)
			continue;
		if(hdr->proto == IPV4_ICMP && sock_table[i]->proto == IPV4_ICMP)
		{
			sock_table[i]->buffer = malloc(sizeof(icmp_header_t));
			if(!sock_table[i]->buffer)
				return;
			icmp_header_t *icmp_packet = (icmp_header_t*)(hdr+1);
			memcpy(sock_table[i]->buffer, icmp_packet, sizeof(icmp_header_t));
		}
		else if(sock_table[i]->localport == dest_port && sock_table[i]->connection_type == SOCK_DGRAM)
		{
			sock_table[i]->buffer = malloc(protocol_len);
			if(!sock_table[i]->buffer)
				return;
			udp_header_t *udp_packet = (udp_header_t*)(hdr+1);
			sock_table[i]->len = protocol_len;
			memset(sock_table[i]->buffer, 0, protocol_len);
			memcpy(sock_table[i]->buffer, &udp_packet->payload, protocol_len);
		}
	}*/

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
