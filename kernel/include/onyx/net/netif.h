/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_NET_NETIF_H
#define _ONYX_NET_NETIF_H
#include <stdint.h>

#include <onyx/vfs.h>
#include <onyx/spinlock.h>
struct netif;
#include <onyx/net/arp.h>

#include <netinet/in.h>
#include <sys/socket.h>

#define NETIF_LINKUP							(1 << 0)
#define NETIF_SUPPORTS_IP_CHECKSUM_OFF			(1 << 1)
#define NETIF_SUPPORTS_TCP_CHECKSUM_OFF			(1 << 2)
#define NETIF_SUPPORTS_ISO						(1 << 3)
#define NETIF_SUPPORTS_TSO						(1 << 4)
#define NETIF_LOOPBACK                          (1 << 5)

/* Defined as an opaque struct since it's C++ TODO: Yuck. */
struct sockets_info;

struct netif
{
	const char *name;
	struct file *device_file;
	void *priv;
	unsigned int flags;
	unsigned int mtu;
	unsigned char mac_address[6];
	struct sockaddr_in local_ip;
	struct sockaddr_in router_ip;
	int (*sendpacket)(const void *buffer, uint16_t size, struct netif *nif);
	struct list_head list_node;
	struct arp_hashtable arp_hashtable;
	struct spinlock hashtable_spinlock;
	struct sockets_info *sock_info;
	struct packetbuf_proto * (*get_packetbuf_proto)(struct netif *n);
	/* To be filled for stuff like virtio */
	struct packetbuf_proto *if_proto;
};

#ifdef __cplusplus
extern "C" {

struct socket_id
{
	int protocol;
	const struct sockaddr &src_addr;
	const struct sockaddr &dst_addr;

	socket_id(int proto, const sockaddr &s, const sockaddr &d) : protocol(proto), src_addr(s), dst_addr(d)
	{}
};

struct socket;
struct inet_socket;

#define GET_SOCKET_UNLOCKED                (1 << 0)
#define GET_SOCKET_DSTADDR_VALID           (1 << 1)
#define GET_SOCKET_CHECK_EXISTANCE         (1 << 2)

#define ADD_SOCKET_UNLOCKED                (1 << 0)
#define REMOVE_SOCKET_UNLOCKED             (1 << 0)


inet_socket *netif_get_socket(const socket_id& id, netif *nif, unsigned int flags = 0);
void netif_lock_socks(const socket_id& id, netif *nif);
void netif_unlock_socks(const socket_id& id, netif *nif);

bool netif_add_socket(inet_socket *sock, netif *nif, unsigned int flags = 0);

void netif_print_open_sockets(netif *nif);

bool netif_remove_socket(inet_socket *sock, netif *nif, unsigned int flags);


#endif

void netif_register_if(struct netif *netif);
int netif_unregister_if(struct netif *netif);
struct netif *netif_choose(void);
int netif_send_packet(struct netif *netif, const void *buffer, uint16_t size);
void netif_get_ipv4_addr(struct sockaddr_in *s, struct netif *netif);
struct netif *netif_get_from_addr(struct sockaddr *s, int domain);
struct list_head *netif_lock_and_get_list(void);
void netif_unlock_list(void);

#ifdef __cplusplus
}
#endif

#endif
