/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_NET_SOCKET_H
#define _ONYX_NET_SOCKET_H

#include <stdint.h>
#include <stddef.h>

#include <onyx/vfs.h>
#include <onyx/object.h>
#include <onyx/semaphore.h>
#include <onyx/hashtable.hpp>
#include <onyx/fnv.h>
#include <onyx/refcount.h>
#include <onyx/wait_queue.h>

#include <onyx/net/proto_family.h>
#include <onyx/net/netif.h>
#include <onyx/vector.h>

#define PROTOCOL_IPV4		1
#define PROTOCOL_IPV6		2
#define PROTOCOL_UDP		3
#define PROTOCOL_TCP		4
#define PROTOCOL_UNIX		5

struct socket_conn_request
{
	struct sockaddr saddr;
	struct list_head list_node;
};

struct socket;

struct sock_ops
{
	int (*listen)(struct socket *sock);
	struct socket *(*accept)(struct socket_conn_request *req, struct socket *sock);
	int (*bind)(struct sockaddr *addr, socklen_t addrlen, struct socket *sock);
	int (*connect)(struct sockaddr *addr, socklen_t addrlen, struct socket *sock);
	ssize_t (*sendto)(const void *buf, size_t len, int flags,
		struct sockaddr *addr, socklen_t addrlen, struct socket *sock);
	ssize_t (*recvfrom)(void *buf, size_t len, int flags, struct sockaddr *addr, 
		socklen_t *slen, struct socket *sock);
};

int default_listen(struct socket *sock);
struct socket *default_accept(struct socket_conn_request *req, struct socket *sock);
int default_bind(const struct sockaddr *addr, socklen_t addrlen, struct socket *sock);
int default_connect(const struct sockaddr *addr, socklen_t addrlen, struct socket *sock);
ssize_t default_sendto(const void *buf, size_t len, int flags,
		struct sockaddr *addr, socklen_t addrlen, struct socket *sock);
ssize_t default_recvfrom(void *buf, size_t len, int flags, struct sockaddr *addr, 
		socklen_t *slen, struct socket *sock);

extern struct sock_ops default_s_ops;

struct recv_packet
{
	sockaddr src_addr;
	socklen_t addr_len;
	void *payload;
	size_t size;
	size_t read;
	list_head_cpp<recv_packet> list_node;
	cul::vector<uint8_t> ancilliary_data;
public:
	recv_packet() : src_addr{}, addr_len{}, payload{}, size{}, read{}, list_node{this}, ancilliary_data{}
	{}

	~recv_packet()
	{
		free(payload);
	}
};

class recv_queue
{
private:
	wait_queue recv_wait;
	struct spinlock recv_queue_lock;
	struct list_head recv_list;
	size_t total_data_in_buffers;
	socket *sock;

	struct list_head *get_recv_packet_list(int msg_flags, size_t required_data, int &error);
	bool has_data_available(int msg_flags, size_t required_data);
	void clear_packets();
public:

	recv_queue(socket *sock) : recv_queue_lock{}, total_data_in_buffers{0}, sock{sock}
	{
		init_wait_queue_head(&recv_wait);
		INIT_LIST_HEAD(&recv_list);
	}

	~recv_queue();

	ssize_t recvfrom(void *buf, size_t len, int flags, sockaddr *src_addr, socklen_t *slen);
	void add_packet(recv_packet *p);
	bool poll(void *poll_file);
};

struct socket : public refcountable
{
	struct object object;
	int type;
	int proto;
	int domain;
	recv_queue in_band_queue;
	recv_queue oob_data_queue;

	/* This mutex serialises binds, connects, listens and accepts on the socket, as to prevent race conditions */
	struct mutex connection_state_lock;
	bool bound;
	bool connected;

	void (*dtor)(struct socket *socket);
	
	struct semaphore listener_sem;
	struct spinlock conn_req_list_lock;
	struct list_head conn_request_list;
	int nr_pending;
	int backlog;

	struct sock_ops *s_ops;
	proto_family *proto_domain;

	/* Define a default constructor here */
	socket() : object{}, type{}, proto{}, domain{}, in_band_queue{this}, oob_data_queue{this}, bound{}, connected{},
               dtor{}, listener_sem{}, conn_req_list_lock{}, conn_request_list{},
			   nr_pending{}, backlog{}, s_ops{&default_s_ops}, proto_domain{}
	{
		mutex_init(&connection_state_lock);
	}

	virtual ~socket()
	{
	}

	ssize_t default_recvfrom(void *buf, size_t len, int flags, sockaddr *src_addr, socklen_t *slen);
	bool has_data_available(int msg_flags, size_t required_data);
	short poll(void *poll_file, short events);
};

template <typename T>
sockaddr &sa_generic(T &s)
{
	return (sockaddr &) s;
}

#ifdef __cplusplus
extern "C" {
#endif

void socket_init(struct socket *socket);

#ifdef __cplusplus
}
#endif

#endif
