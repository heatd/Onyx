/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_NET_NETWORK_H
#define _ONYX_NET_NETWORK_H

#include <stdint.h>
#include <stdbool.h>

#include <onyx/vfs.h>

#ifdef __cplusplus
#include <onyx/net/socket.h>
#endif

#include <sys/socket.h>

struct network_args
{
	uint8_t *buffer;
	uint16_t size;
	struct netif *netif;
};

#ifdef __cplusplus
extern "C" {
#endif

void network_dispatch_recieve(uint8_t *packet, uint16_t len, struct netif *netif);
int network_handle_packet(uint8_t *packet, uint16_t len, struct netif *netif);
const char *network_gethostname();
void network_sethostname(const char *);

#ifdef __cplusplus
}
#endif
#endif
