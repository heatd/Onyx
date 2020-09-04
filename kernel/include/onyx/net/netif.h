/*
* Copyright (c) 2017-2020 Pedro Falcato
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
#include <onyx/net/dll.h>
#include <onyx/vector.h>

#include <netinet/in.h>
#include <onyx/public/socket.h>

#define NETIF_LINKUP							(1 << 0)
#define NETIF_SUPPORTS_CSUM_OFFLOAD			    (1 << 1)
#define NETIF_SUPPORTS_TSO4						(1 << 3)
#define NETIF_SUPPORTS_TSO6						(1 << 4)
#define NETIF_SUPPORTS_UFO                      (1 << 5)
#define NETIF_LOOPBACK                          (1 << 5)
#define NETIF_HAS_RX_AVAILABLE                  (1 << 6)
#define NETIF_DOING_RX_POLL                     (1 << 7)
#define NETIF_MISSED_RX                         (1 << 8)

/* Defined as an opaque struct since it's C++ TODO: Yuck. */

struct packetbuf;

struct netif
{
	const char *name;
	struct file *device_file;
	void *priv;
	unsigned int flags;
	unsigned int mtu;
	unsigned char mac_address[6];
	struct sockaddr_in local_ip;
	in6_addr local_ip6;
	int (*sendpacket)(packetbuf *buf, struct netif *nif);
	int (*poll_rx)(struct netif *nif);
	void (*rx_end)(struct netif *nif);
	struct list_head list_node;
	struct list_head rx_queue_node;
	data_link_layer_ops *dll_ops;
};

#ifdef __cplusplus
extern "C" {

struct inet_sock_address;

struct socket_id
{
	int protocol;
	int domain;
	const struct inet_sock_address &src_addr;
	const struct inet_sock_address &dst_addr;

	socket_id(int proto, int domain, const inet_sock_address &s, const inet_sock_address &d)
	: protocol{proto}, domain{domain}, src_addr{s}, dst_addr{d}
	{}
};

struct socket;
struct inet_socket;

#define GET_SOCKET_UNLOCKED                (1 << 0)
#define GET_SOCKET_DSTADDR_VALID           (1 << 1)
#define GET_SOCKET_CHECK_EXISTENCE         (1 << 2)

#define ADD_SOCKET_UNLOCKED                (1 << 0)
#define REMOVE_SOCKET_UNLOCKED             (1 << 0)

int netif_send_packet(struct netif *netif, packetbuf *buf);


#endif

void netif_register_if(struct netif *netif);
int netif_unregister_if(struct netif *netif);
struct netif *netif_choose(void);
void netif_get_ipv4_addr(struct sockaddr_in *s, struct netif *netif);
struct netif *netif_get_from_addr(const inet_sock_address& s, int domain);
cul::vector<netif*>& netif_lock_and_get_list(void);
void netif_unlock_list(void);
struct netif *netif_from_name(const char *name);
int netif_do_rx(void);
void netif_signal_rx(netif *nif);
int netif_process_pbuf(netif *nif, packetbuf *buf);

#ifdef __cplusplus
}
#endif

#endif
