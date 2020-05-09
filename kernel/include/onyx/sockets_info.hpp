/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_SOCKETS_INFO_HPP
#define _ONYX_SOCKETS_INFO_HPP

#include <onyx/ip.h>

#include <onyx/hashtable.hpp>
#include <onyx/spinlock.h>

struct sockets_info
{
	cul::hashtable<struct inet_socket *, 512, uint32_t, &inet_socket::make_hash> socket_hashtable;
	struct spinlock lock;
};

#endif
