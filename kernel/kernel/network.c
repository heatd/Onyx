/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <kernel/network.h>
#include <kernel/udp.h>
#include <kernel/compiler.h>

socket_t *sock_table[MAX_NETWORK_CONNECTIONS] = {0};
int socket(int domain, int type, int protocol)
{
	if(domain != AF_INET)
		return errno = ENOSYS, -1;
	if(type != SOCK_DGRAM)
		return errno = ENOSYS, -1;
	UNUSED(protocol);

	socket_t *sock = malloc(sizeof(socket_t));
	if(!sock)
		return errno = ENOMEM, -1;
	memset(sock, 0, sizeof(socket_t));
	
	sock->mode = SOCK_RDONLY;
	sock->domain = domain;
	sock->connection_type = type;
	for(int i = 0; i < MAX_NETWORK_CONNECTIONS; i++)
	{
		if(sock_table[i] == NULL)
		{
			sock_table[i] = sock;
			return i;
		}
	}
	return errno = EADDRNOTAVAIL, -1;
}
int bind(int socket, int localport, uint32_t ip, int destport)
{
	if(socket > MAX_NETWORK_CONNECTIONS)
		return errno = EINVAL, -1;
	socket_t *sock = sock_table[socket];
	if(!sock)
		return errno = EINVAL, 1;
	sock->localport = localport;
	sock->remote_ip = ip;
	sock->remote_port = destport;

	sock->mode = SOCK_RDWR;

	return 0;
}
int recv(int socket, void **bufptr)
{
	if(socket > MAX_NETWORK_CONNECTIONS)
		return errno = EINVAL, -1;
	socket_t *sock = sock_table[socket];
	if(!sock)
		return errno = EINVAL, 1;
	while(!sock->buffer);
	*bufptr = sock->buffer;
	sock->buffer = NULL;
	return sock->len;
}
extern uint32_t local_ip;
int send(int socket, const void *buffer, size_t len)
{
	if(socket > MAX_NETWORK_CONNECTIONS)
		return errno = EINVAL, -1;
	socket_t *sock = sock_table[socket];
	if(!sock)
		return errno = EINVAL, 1;
	return send_udp_packet(buffer, len, sock->localport, sock->remote_port, local_ip, sock->remote_ip);
}
void network_handle_packet(ip_header_t *hdr, uint16_t len)
{
	hdr->source_ip = LITTLE_TO_BIG32(hdr->source_ip);
	uint32_t ip = hdr->source_ip;
	int source_port, dest_port;
	int protocol_len = 0;
	switch(hdr->proto)
	{
		case IPV4_UDP:
		{
			udp_header_t *udp_packet = (udp_header_t*)&hdr->payload;
			source_port = LITTLE_TO_BIG16(udp_packet->source_port);
			udp_packet->dest_port = LITTLE_TO_BIG16(udp_packet->dest_port);
			dest_port = udp_packet->dest_port;
			udp_packet->len = LITTLE_TO_BIG16(udp_packet->len);
			protocol_len = udp_packet->len;
			break;
		}
	}
	
	for(int i = 0; i < MAX_NETWORK_CONNECTIONS; i++)
	{
		if(sock_table[i] == NULL)
			continue;
		if(sock_table[i]->localport == dest_port && sock_table[i]->connection_type == SOCK_DGRAM)
		{
			sock_table[i]->buffer = malloc(protocol_len);
			if(!sock_table[i]->buffer)
				return;
			udp_header_t *udp_packet = (udp_header_t*)(hdr+1);
			sock_table[i]->len = protocol_len;
			memset(sock_table[i]->buffer, 0, protocol_len);
			memcpy(sock_table[i]->buffer, &udp_packet->payload, protocol_len);
		}
	}

}