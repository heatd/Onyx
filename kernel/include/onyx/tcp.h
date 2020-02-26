/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_TCP_H
#define _ONYX_TCP_H

#include <stdint.h>
#include <stddef.h>

#include <onyx/semaphore.h>
#include <onyx/socket.h>

struct tcp_header
{
	uint16_t source_port;
	uint16_t dest_port;
	uint32_t sequence_number;
	uint32_t ack_number;
	uint16_t data_offset_and_flags;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_pointer;
	uint8_t options[];
};

#define TCP_FLAG_FIN			(1 << 0)
#define TCP_FLAG_SYN			(1 << 1)
#define TCP_FLAG_RST			(1 << 2)
#define TCP_FLAG_PSH			(1 << 3)
#define TCP_FLAG_ACK			(1 << 4)
#define TCP_FLAG_URG			(1 << 5)
#define TCP_FLAG_ECE			(1 << 6)
#define TCP_FLAG_CWR			(1 << 7)
#define TCP_FLAG_NS				(1 << 8)
#define TCP_DATA_OFFSET_SHIFT	(12)
#define TCP_DATA_OFFSET_MASK	(0xf)

enum tcp_state
{
	TCP_STATE_LISTEN = 0,
	TCP_STATE_SYN_SENT,
	TCP_STATE_SYN_RECIEVED,
	TCP_STATE_ESTABLISHED,
	TCP_STATE_FIN_WAIT_1,
	TCP_STATE_FIN_WAIT_2,
	TCP_STATE_CLOSE_WAIT,
	TCP_STATE_CLOSING,
	TCP_STATE_LAST_ACK,
	TCP_STATE_TIME_WAIT,
	TCP_STATE_CLOSED
};

struct tcp_packet
{
	struct sockaddr_in addr;
	void *payload;
	size_t size;
	struct list_head packet_list_memb;
};

struct tcp_socket
{
	struct socket socket;
	enum tcp_state state;
	int type;
	struct sockaddr_in src_addr;
	struct sockaddr_in dest_addr;
	struct semaphore packet_semaphore;
	struct list_head packet_list_head;
	struct spinlock packet_lock;
	struct list_head socket_list_head;
};

struct socket *tcp_create_socket(int type);
int tcp_init_netif(struct netif *netif);

#endif