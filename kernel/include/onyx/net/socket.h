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
#include <onyx/pair.hpp>
#include <onyx/expected.hpp>

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


static inline ssize_t iovec_count_length(iovec *vec, unsigned int n)
{
	ssize_t length = 0;

	while(n--)
	{
		if((ssize_t) vec->iov_len < 0)
			return -EINVAL;
		
		if(__builtin_saddl_overflow(length, vec->iov_len, &length))
			return -EINVAL;

		vec++;
	}

	return length;
}

struct recv_packet
{
	union
	{
		sockaddr_in in4;
		sockaddr_in6 in6;
	} src_addr;

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
private:

	template <typename Type>
	static int __put_option(const Type &val, socklen_t buflen, void *option)
	{
		return copy_to_user(option, &val, cul::min(sizeof(val), (size_t) buflen));
	}
	
	static int adjust_option_length(socklen_t *ulen, socklen_t buflen, socklen_t actual_length)
	{
		return buflen != actual_length ? 0 : copy_to_user(ulen, &actual_length, sizeof(actual_length));
	}

public:
	int type;
	int proto;
	int domain;
	recv_queue in_band_queue;
	recv_queue oob_data_queue;
	unsigned int flags;
	unsigned int sock_err;

	/* This mutex serialises binds, connects, listens and accepts on the socket,
	 * as to prevent race conditions.
	 */

	struct mutex connection_state_lock;
	bool bound;
	bool connected;

	struct semaphore listener_sem;
	struct spinlock conn_req_list_lock;
	struct list_head conn_request_list;
	int nr_pending;
	int backlog;

	proto_family *proto_domain;

	/* Define a default constructor here */
	socket() : type{}, proto{}, domain{}, in_band_queue{this}, oob_data_queue{this},
               flags{}, sock_err{}, bound{}, connected{},
               listener_sem{}, conn_req_list_lock{}, conn_request_list{},
			   nr_pending{}, backlog{}, proto_domain{}
	{
		mutex_init(&connection_state_lock);
	}

	virtual ~socket()
	{
	}

	ssize_t default_recvfrom(void *buf, size_t len, int flags, sockaddr *src_addr, socklen_t *slen);
	bool has_data_available(int msg_flags, size_t required_data);
	virtual short poll(void *poll_file, short events);

	template <typename Type>
	expected<Type, int> get_socket_option(void *optval, const socklen_t *optlen)
	{
		socklen_t len;

		if(copy_from_user(&len, optlen, sizeof(len)) < 0)
			return unexpected<int>{-EFAULT};

		if(len != sizeof(Type))
			return unexpected<int>{-EINVAL};

		Type t;
		if(copy_from_user(&t, optval, len) < 0)
			return unexpected<int>{-EFAULT};

		return cul::move(t);
	}

	int getsockopt_socket_level(int optname, void *optval, socklen_t *optlen);
	int setsockopt_socket_level(int optname, const void *optval, socklen_t optlen);

	template <typename Type>
	static int put_option(const Type &val, socklen_t buflen, socklen_t *ulen, void *option)
	{
		if(__put_option(val, buflen, option) < 0)
			return -EFAULT;
		if(adjust_option_length(ulen, buflen, sizeof(val)) < 0)
			return -EFAULT;
		return 0;
	}

	bool listening() const
	{
		return backlog != 0;
	}

	static bool int_to_truthy(int i)
	{
		return i != 0;
	}

	virtual int listen();
	virtual socket *accept(socket_conn_request *req);
	virtual int bind(sockaddr *addr, socklen_t addrlen);
	virtual int connect(sockaddr *addr, socklen_t addrlen);
	virtual ssize_t sendmsg(const struct msghdr *msg,	int flags);
	virtual ssize_t recvmsg(struct msghdr *msg, int flags);
	virtual int getsockopt(int level, int optname, void *optval, socklen_t *optlen) = 0;
	virtual int setsockopt(int level, int optname, const void *optval, socklen_t optlen) = 0;
};

template <typename T>
sockaddr &sa_generic(T &s)
{
	return (sockaddr &) s;
}

#define SOL_ICMP       1
#define SOL_TCP        6
#define SOL_UDP        21

#ifdef __cplusplus
extern "C" {
#endif

void socket_init(struct socket *socket);

#ifdef __cplusplus
}
#endif

#endif
