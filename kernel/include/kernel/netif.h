/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_NETIF_H
#define _KERNEL_NETIF_H
#include <stdint.h>

#include <kernel/vfs.h>
#include <kernel/spinlock.h>
struct netif;
#include <kernel/arp.h>

#include <netinet/in.h>
#include <sys/socket.h>

struct udp_socket;
#define NETIF_LINKUP		(1 << 0)
struct netif
{
	const char *name;
	struct inode *device_file;
	unsigned int flags;
	unsigned char mac_address[6];
	unsigned char router_mac[6];
	struct sockaddr local_ip;
	struct sockaddr router_ip;
	int (*sendpacket)(const void *buffer, uint16_t size);
	struct netif *next;
	struct arp_hashtable arp_hashtable;
	spinlock_t hashtable_spinlock;
	struct udp_socket **udp_ports;
};
#ifdef __cplusplus
extern "C" {
#endif
void netif_register_if(struct netif *netif);
int netif_unregister_if(struct netif *netif);
struct netif *netif_choose(void);
int netif_send_packet(struct netif *netif, const void *buffer, uint16_t size);
void netif_get_ipv4_addr(struct sockaddr_in *s, struct netif *netif);
#ifdef __cplusplus
}
#endif
#endif
