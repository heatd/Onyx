/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_PUBLIC_NETKERNEL_H
#define _ONYX_PUBLIC_NETKERNEL_H

#include <sys/socket.h>

#include <netinet/in.h>

struct netkernel_hdr
{
	unsigned int msg_type;
	unsigned int flags;
	unsigned long size;
	unsigned char data[0];
};

struct netkernel_error
{
	struct netkernel_hdr hdr;
	int error;
};

#define NETKERNEL_MSG_ERROR           0


#define NETKERNEL_MSG_ROUTE4_ADD      0x1000

#define NETKERNEL_PATH_MAX            109

struct sockaddr_nk
{
	sa_family_t nk_family;
	/* netkernel addresses are expressed through a 109 character dot-separated path, 
	 * and are null terminated.
	 */
	char path[NETKERNEL_PATH_MAX + 1];
};

#define IF_NAME_MAX        10

struct netkernel_route4_add
{
	struct netkernel_hdr hdr;
	in_addr dest;
	in_addr gateway;
	in_addr mask;
	int metric;
	unsigned short flags;
	char iface[IF_NAME_MAX + 1];
};

#define ROUTE4_FLAG_GATEWAY      (1 << 0)

#endif
