/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include <onyx/log.h>
#include <onyx/network.h>
#include <onyx/ip.h>
#include <onyx/udp.h>
#include <onyx/icmp.h>
#include <onyx/compiler.h>
#include <onyx/dns.h>
#include <onyx/file.h>
#include <onyx/ethernet.h>
#include <onyx/dpc.h>
#include <onyx/network.h>
#include <onyx/slab.h>

static const char *hostname = "";

int network_handle_packet(uint8_t *packet, uint16_t len, struct netif *netif)
{
	ethernet_header_t *hdr = (ethernet_header_t*) packet;
	hdr->ethertype = LITTLE_TO_BIG16(hdr->ethertype);
	if(hdr->ethertype == PROTO_IPV4)
		ipv4_handle_packet((ip_header_t*)(hdr+1), len - sizeof(ethernet_header_t), netif);
	/*else if(hdr->ethertype == PROTO_ARP)
		arp_handle_packet((arp_request_t*)(hdr+1), len - sizeof(ethernet_header_t));*/
	return 0;
}

const char *network_gethostname()
{
	return hostname;
}

void network_sethostname(const char *name)
{
	/* TODO: Invalidate the dns cache entry of the last host name */
	if(strcmp((char*) hostname, ""))
		free((void *) hostname);
	hostname = name;
}

int check_af_support(int domain)
{
	switch(domain)
	{
		case AF_INET:
			return 0;
		case AF_UNIX:
			return 0;
		default:
			return -1;
	}
}

static const int type_mask = SOCK_DGRAM | SOCK_STREAM | SOCK_SEQPACKET;
static const int sock_flag_mask = ~type_mask;

int net_check_type_support(int type)
{
	(void) sock_flag_mask;
	return type & type_mask;
}

int net_autodetect_protocol(int type, int domain)
{
	switch(type & type_mask)
	{
		case SOCK_DGRAM:
		{
			if(domain == AF_UNIX)
				return PROTOCOL_UNIX;
			else if(domain == AF_INET)
				return PROTOCOL_UDP;
			else
				return -1;
		}
		case SOCK_RAW:
		{
			if(domain == AF_INET)
				return PROTOCOL_IPV4;
			else if(domain == AF_UNIX)
				return PROTOCOL_UNIX;
			return -1;
		}
		case SOCK_STREAM:
			return PROTOCOL_TCP;
	}

	return -1;
}

struct socket *unix_create_socket(int type, int protocol);

struct socket *socket_create(int domain, int type, int protocol)
{
	switch(domain)
	{
		case AF_INET:
			return ipv4_create_socket(type, protocol);
			return errno = EAFNOSUPPORT, NULL;
		case AF_UNIX:
			return unix_create_socket(type, protocol);
		default:
			return errno = EAFNOSUPPORT, NULL;
	}
}

struct inode *socket_create_inode(struct socket *socket)
{
	struct inode *inode = inode_create();

	if(!inode)
		return NULL;
	
	assert(socket->ops != NULL);

	memcpy(&inode->i_fops, socket->ops, sizeof(struct file_ops));

	inode->i_type = VFS_TYPE_UNIX_SOCK;
	inode->i_helper = socket;

	return inode;
}

int sys_socket(int domain, int type, int protocol)
{
	int dflags;
	dflags = O_RDWR;
	if(check_af_support(domain) < 0)
		return -EAFNOSUPPORT;
	if(net_check_type_support(type) < 0)
		return -EINVAL;

	if(protocol == 0)
	{
		/* If protocol == 0, auto-detect the proto */
		if((protocol = net_autodetect_protocol(type, domain)) < 0)
			return -EINVAL;
	}

	/* Create the socket */
	struct socket *socket = socket_create(domain, type, protocol);
	if(!socket)
		return -errno;
	
	struct inode *inode = socket_create_inode(socket);
	if(!inode)
		return -errno;

	if(type & SOCK_CLOEXEC)
		dflags |= O_CLOEXEC;

	/* Open a file descriptor with the socket vnode */
	int fd = open_with_vnode(inode, dflags);
	/* If we failed, close the socket and return */
	if(fd < 0)
		close_vfs((struct inode*) socket);
	return fd;
}

static slab_cache_t *network_slab;

void network_do_dispatch(void *__args)
{
	struct network_args *args = __args;
	network_handle_packet(args->buffer, args->size, args->netif);
	slab_free(network_slab, __args);
}

#ifndef NET_POOL_NUM_OBJS
#define NET_POOL_NUM_OBJS	512
#endif

void __init network_init(void)
{
	network_slab = slab_create("net", sizeof(struct network_args), 0,
			SLAB_FLAG_POOL, NULL, NULL);
	assert(network_slab != NULL);

	assert(slab_populate(network_slab, NET_POOL_NUM_OBJS) != -1);
}

void network_dispatch_recieve(uint8_t *packet, uint16_t len, struct netif *netif)
{
	struct network_args *args = slab_allocate(network_slab);
	if(!args)
	{
		ERROR("net", "Could not recieve packet: Out of memory inside IRQ\n");
		return;
	}

	args->buffer = packet;
	args->size = len;
	args->netif = netif;

	struct dpc_work work = {0};
	work.funcptr = network_do_dispatch;
	work.context = args;
	dpc_schedule_work(&work, DPC_PRIORITY_HIGH);
}
