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
#ifndef _KERNEL_NETWORK_H
#define _KERNEL_NETWORK_H

#include <stdint.h>

#include <kernel/ip.h>

#define SOCK_DGRAM 1
#define AF_INET 1

#define SOCK_RAW 2
#define SOCK_RDONLY 1
#define SOCK_WR 2
#define SOCK_RDWR 4

#define MAX_NETWORK_CONNECTIONS 200
typedef struct sock
{
	int mode;
	int proto;
	int connection_type;
	int domain;
	int localport;
	int remote_port;
	uint32_t remote_ip;
	size_t len;
	char *buffer;
} socket_t;


int socket(int domain, int connection_type, int protocol);
int bind(int socket, int localport, uint32_t ip, int destport);
int recv(int socket, void **bufptr);
int send(int socket, const void *buffer, size_t len);
void network_handle_packet(ip_header_t *hdr, uint16_t len);



#endif
