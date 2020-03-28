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
#include <onyx/mutex.h>
#include <onyx/condvar.h>

#ifdef __cplusplus
#include <onyx/vector.h>
#endif

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
} __attribute__((packed));

#define TCP_FLAG_FIN			(uint16_t)(1 << 0)
#define TCP_FLAG_SYN			(uint16_t)(1 << 1)
#define TCP_FLAG_RST			(uint16_t)(1 << 2)
#define TCP_FLAG_PSH			(uint16_t)(1 << 3)
#define TCP_FLAG_ACK			(uint16_t)(1 << 4)
#define TCP_FLAG_URG			(uint16_t)(1 << 5)
#define TCP_FLAG_ECE			(uint16_t)(1 << 6)
#define TCP_FLAG_CWR			(uint16_t)(1 << 7)
#define TCP_FLAG_NS				(uint16_t)(1 << 8)
#define TCP_DATA_OFFSET_SHIFT	(12)
#define TCP_DATA_OFFSET_MASK	(0xf)

#ifdef __cplusplus

enum class tcp_state
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

class tcp_ack
{
private:
	tcp_header *packet;
	uint16_t length;
public:
	list_head list_node;

	tcp_ack(tcp_header *packet, uint16_t length)
	        : packet(packet), length(length)
	{
	}

	~tcp_ack()
	{
		free(packet);
	}

	void append(list_head *head)
	{
		list_add(&list_node, head);
	}

	void remove()
	{
		list_remove(&list_node);
	}

	tcp_header *get_packet() const
	{
		return packet;
	}

	uint16_t get_length() const
	{
		return length;
	}
};

class tcp_socket : public socket
{
private:
	enum tcp_state state;
	int type;
	struct sockaddr_in src_addr;
	struct sockaddr_in dest_addr;
	struct semaphore packet_semaphore;
	struct list_head packet_list_head;
	struct spinlock packet_lock;
	mutex tcp_ack_list_lock;
	struct list_head tcp_ack_list;
	cond tcp_ack_cond;
	uint32_t seq_number;
	uint32_t ack_number;
	mutex send_buffer_lock;
	cul::vector<uint8_t> send_buffer;
	size_t current_pos;

	template <typename pred>
	tcp_ack *find_ack(pred predicate)
	{
		list_for_every(&tcp_ack_list)
		{
			tcp_ack *ack = container_of(l, tcp_ack, list_node);
			if(predicate(ack))
				return ack;
		}

		return nullptr;
	}

	template <typename pred>
	tcp_ack *wait_for_ack(pred predicate)
	{
		/* TODO: Add timeouts */
		mutex_lock(&tcp_ack_list_lock);

		while(true)
		{
			auto found_ack = find_ack(predicate);
			if(found_ack)
			{
				found_ack->remove();
				mutex_unlock(&tcp_ack_list_lock);
				return found_ack;				
			}

			condvar_wait(&tcp_ack_cond, &tcp_ack_list_lock);
		}
	}

	int send_syn_ack(uint16_t flags);

public:
	struct list_head socket_list_head;

	tcp_socket() : socket{}, state(tcp_state::TCP_STATE_CLOSED), type(SOCK_STREAM),
	               src_addr{}, dest_addr{}, packet_semaphore{}, packet_list_head{},
				   packet_lock{}, tcp_ack_list_lock{}, tcp_ack_cond{},
				   seq_number{0}, ack_number{0}, send_buffer_lock{}, send_buffer{},
				   current_pos{}, socket_list_head{}
	{
		INIT_LIST_HEAD(&tcp_ack_list);
	}

	~tcp_socket()
	{
		assert(state == tcp_state::TCP_STATE_CLOSED);
	}

	struct sockaddr_in &saddr() {return src_addr;}
	struct sockaddr_in &daddr() {return dest_addr;}

	int bind(const struct sockaddr *addr, socklen_t addrlen);
	int connect(const struct sockaddr *addr, socklen_t addrlen);

	int start_connection();

	void append_ack(tcp_ack *ack)
	{
		mutex_lock(&tcp_ack_list_lock);
		ack->append(&tcp_ack_list);
		condvar_broadcast(&tcp_ack_cond);
		mutex_unlock(&tcp_ack_list_lock);
	}

	ssize_t sendto(const void *buf, size_t len, int flags);
};

#endif

#ifdef __cplusplus
extern "C" {
#endif

struct socket *tcp_create_socket(int type);
int tcp_init_netif(struct netif *netif);
int tcp_handle_packet(struct ip_header *header, size_t size, struct netif *netif);

#ifdef __cplusplus
}
#endif

#endif