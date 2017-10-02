/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_NETWORK_H
#define _KERNEL_NETWORK_H

#include <stdint.h>
#include <stdbool.h>

#include <onyx/ip.h>
#include <onyx/vfs.h>

#include <sys/socket.h>

#define PROTOCOL_IPV4		1
#define PROTOCOL_IPV6		2
#define PROTOCOL_UDP		3
#define PROTOCOL_TCP		4

#define SOCK_RDONLY 1
#define SOCK_WR 2
#define SOCK_RDWR 4

#define MAX_NETWORK_CONNECTIONS 200
typedef struct sock
{
	struct inode node;
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
} socket_t;


struct network_args
{
	uint8_t *buffer;
	uint16_t size;
	struct netif *netif;
};

#ifdef __cplusplus
extern "C" {
#endif

int _socket(int domain, int connection_type, int protocol);
int _bind(int socket, int localport, uint32_t ip, int destport);
int _recv(int socket, void **bufptr);
int _send(int socket, const void *buffer, size_t len);
void network_dispatch_recieve(uint8_t *packet, uint16_t len, struct netif *netif);
int network_handle_packet(uint8_t *packet, uint16_t len, struct netif *netif);
const char *network_gethostname();
void network_sethostname(const char *);

#ifdef __cplusplus
}
#endif
#endif
