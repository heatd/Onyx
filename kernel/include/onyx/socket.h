/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_SOCKET_H
#define _ONYX_SOCKET_H

#include <stdint.h>
#include <stddef.h>

#include <onyx/vfs.h>
#include <onyx/object.h>
#include <onyx/netif.h>
#include <onyx/semaphore.h>

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
	int (*bind)(const struct sockaddr *addr, socklen_t addrlen, struct socket *sock);
	int (*connect)(const struct sockaddr *addr, socklen_t addrlen, struct socket *sock);
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

struct socket
{
	struct object object;
	int type;
	int proto;
	int domain;
	struct netif *netif;
	bool bound;
	bool connected;

	void (*dtor)(struct socket *socket);
	
	struct semaphore listener_sem;
	struct spinlock conn_req_list_lock;
	struct list_head conn_request_list;
	int nr_pending;
	int backlog;

	struct sock_ops *s_ops;

#ifdef __cplusplus
	/* Define a default constructor here */
	socket() : object{}, type{}, proto{}, domain{}, netif{}, bound{}, connected{},
               dtor{}, listener_sem{}, conn_req_list_lock{}, conn_request_list{},
			   nr_pending{}, backlog{}, s_ops{&default_s_ops}
	{}
#endif
};

#ifdef __cplusplus
extern "C" {
#endif

void socket_init(struct socket *socket);
void socket_ref(struct socket *socket);
void socket_unref(struct socket *socket);

#ifdef __cplusplus
}
#endif

#endif