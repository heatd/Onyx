/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_NET_UDP_H
#define _ONYX_NET_UDP_H

#include <stdint.h>

#include <onyx/semaphore.h>
#include <onyx/wait_queue.h>
#include <onyx/scoped_lock.h>

#include <onyx/net/ip.h>
#include <onyx/net/network.h>


struct udphdr
{
	uint16_t source_port;
	uint16_t dest_port;
	uint16_t len;
	uint16_t checksum;
};

struct udp_packet
{
	struct sockaddr_in addr;
	void *payload;
	size_t size;
	struct udp_packet *next;
};

#define UDP_CORK	1
#define UDP_ENCAP	100

#define UDP_ENCAP_ESPINUDP_NON_IKE 1
#define UDP_ENCAP_ESPINUDP	2
#define UDP_ENCAP_L2TPINUDP	3
#define UDP_ENCAP_GTP0		4
#define UDP_ENCAP_GTP1U		5

class udp_socket : public inet_socket
{
	packetbuf *get_rx_head()
	{
		if(list_is_empty(&rx_packet_list))
			return nullptr;
		
		return list_head_cpp<packetbuf>::self_from_list_head(list_first_element(&rx_packet_list));
	}

	bool has_data_available()
	{
		return !list_is_empty(&rx_packet_list);
	}

	expected<packetbuf *, int> get_datagram(int flags);

	int wait_for_dgrams()
	{
		return wait_for_event_locked_interruptible(&rx_wq, !list_is_empty(&rx_packet_list), &rx_packet_list_lock);
	}

	template <typename AddrType>
	ssize_t udp_sendmsg(const msghdr *msg, int flags, const inet_sock_address& dst);

	unsigned int wants_cork : 1;

public:
	udp_socket() : wants_cork{0} {}

	int bind(sockaddr *addr, socklen_t len) override;
	int connect(sockaddr *addr, socklen_t len) override;
	ssize_t sendmsg(const msghdr *msg, int flags) override;
	int getsockopt(int level, int optname, void *val, socklen_t *len) override;
	int setsockopt(int level, int optname, const void *val, socklen_t len) override;
	int send_packet(const msghdr *msg, ssize_t payload_size, in_port_t source_port, in_port_t dest_port,
	                inet_route& route, int msg_domain);
	ssize_t recvmsg(msghdr *msg, int flags) override;

	void rx_dgram(packetbuf *buf)
	{
		append_inet_rx_pbuf(buf);
	}

	short poll(void *poll_file, short events) override;
};

struct socket *udp_create_socket(int type);
int udp_init_netif(struct netif *netif);
int udp_handle_packet(netif *netif, packetbuf *buf);
int udp_handle_packet_v6(netif *netif, packetbuf *buf);

#endif
