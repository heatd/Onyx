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
#include <onyx/slice.hpp>

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

#define TCP_OPTION_END_OF_OPTIONS		(0)
#define TCP_OPTION_NOP					(1)
#define TCP_OPTION_MSS					(2)
#define TCP_OPTION_WINDOW_SCALE			(3)
#define TCP_OPTION_SACK_PERMITTED		(4)
#define TCP_OPTION_SACK					(5)
#define TCP_OPTION_TIMESTAMP			(8)

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

class tcp_option
{
public:
	/* Lets use a static buffer to simplify things, using the length of SACK as the largest (since it is atm).
	 * This won't need to be future proof since we can progressively update it as time goes on,
	 * since we won't send options we're not aware of.
	 */

	static constexpr uint8_t largest_length = (34 - 2);
	uint8_t kind;
	uint8_t length;
	union
	{
		uint16_t mss;
		uint8_t window_scale_shift;
		uint8_t _data[largest_length];
	} data;
	/* If it was allocated dynamically, the tcp_packet dtor needs to delete it */
	uint8_t dynamic;

	struct list_head list_node;

	tcp_option(uint8_t kind, uint8_t length) : kind{kind}, length{length}, dynamic{0} {}

	~tcp_option() {}


};

class tcp_socket;

class tcp_packet
{
private:
	cul::slice<const uint8_t> payload;
	tcp_socket *socket;
	struct list_head option_list;
	uint16_t flags;

	void delete_options()
	{
		list_for_every_safe(&option_list)
		{
			tcp_option *opt = container_of(l, tcp_option, list_node);

			list_remove(l);
			if(opt->dynamic)
				delete opt;
		}
	}

	void put_options(char *opts);

public:
	tcp_packet(cul::slice<const uint8_t> data, tcp_socket *socket, uint16_t flags) : payload(data),
	           socket(socket), flags(flags)
	{
		INIT_LIST_HEAD(&option_list);
	}

	~tcp_packet()
	{
		delete_options();
	}

	uint16_t options_length() const;

	int send();

	tcp_socket *get_socket()
	{
		return socket;
	}

	void append_option(tcp_option *opt)
	{
		list_add(&opt->list_node, &option_list);
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
	mutex send_lock;
	cul::vector<uint8_t> send_buffer;
	size_t current_pos;
	uint16_t mss;
	uint32_t window_size;
	uint8_t window_size_shift;
	uint32_t our_window_size;
	uint8_t our_window_shift;
	uint32_t expected_ack;

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

	int start_handshake();
	int finish_handshake();

	bool parse_options(tcp_header *packet);

public:
	friend class tcp_packet;
	struct list_head socket_list_head;

	static constexpr uint16_t default_mss = 536;
	static constexpr uint16_t default_window_size_shift = 0;

	tcp_socket() : socket{}, state(tcp_state::TCP_STATE_CLOSED), type(SOCK_STREAM),
	               src_addr{}, dest_addr{}, packet_semaphore{}, packet_list_head{},
				   packet_lock{}, tcp_ack_list_lock{}, tcp_ack_cond{},
				   seq_number{0}, ack_number{0}, send_lock{}, send_buffer{},
				   current_pos{}, mss{default_mss}, window_size{0},
				   window_size_shift{default_window_size_shift}, our_window_size{UINT16_MAX},
				   our_window_shift{default_window_size_shift}, expected_ack{0}
	{
		INIT_LIST_HEAD(&tcp_ack_list);
		mutex_init(&tcp_ack_list_lock);
		mutex_init(&send_lock);
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

	uint32_t sequence_nr()
	{
		return seq_number;
	}

	uint32_t acknowledge_nr()
	{
		return ack_number;
	}

	ssize_t queue_data(const void *user_buf, size_t len);

	void try_to_send();
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
