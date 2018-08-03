/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_SOCKET_H
#define _ONYX_SOCKET_H

#include <stdint.h>

#include <onyx/vfs.h>
#include <onyx/object.h>
#include <onyx/netif.h>

#define PROTOCOL_IPV4		1
#define PROTOCOL_IPV6		2
#define PROTOCOL_UDP		3
#define PROTOCOL_TCP		4
#define PROTOCOL_UNIX		5

struct socket
{
	struct object object;
	int mode;
	int proto;
	int connection_type;
	int domain;
	int localport;
	int remote_port;
	uint32_t remote_ip;
	size_t len;
	char *buffer;
	struct netif *netif;
	bool bound;
	bool connected;

	struct file_ops *ops;
	void (*dtor)(struct socket *socket);
};

void socket_init(struct socket *socket);
void socket_ref(struct socket *socket);
void socket_unref(struct socket *socket);

#endif