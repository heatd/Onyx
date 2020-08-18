/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_NET_INET_PROTO_FAMILY_H
#define _ONYX_NET_INET_PROTO_FAMILY_H

#include <onyx/net/inet_route.h>

struct netif;

struct inet_socket;

class inet_proto_family : public proto_family
{
public:
	virtual int bind(struct sockaddr *addr, socklen_t len, inet_socket *socket) = 0;
	virtual int bind_any(inet_socket *sock) = 0;
	virtual expected<inet_route, int> route(const inet_sock_address& from, const inet_sock_address &to, int domain) = 0;
	virtual void unbind_one(netif *nif, inet_socket *sock) = 0;
};

#endif
