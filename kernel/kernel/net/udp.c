/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>

#include <onyx/dev.h>
#include <onyx/ip.h>
#include <onyx/udp.h>
#include <onyx/netif.h>
#include <onyx/compiler.h>

#include <netinet/in.h>

int send_udp_packet(char *payload, size_t payload_size, int source_port, int dest_port, uint32_t srcip, uint32_t destip, struct netif *netif)
{
	udp_header_t *udp_header = malloc(sizeof(udp_header_t) + payload_size);
	if(!udp_header)
		return errno = ENOMEM, 1;
	memset(udp_header, 0, sizeof(udp_header_t) + payload_size);
	udp_header->source_port = LITTLE_TO_BIG16(source_port);
	udp_header->dest_port = LITTLE_TO_BIG16(dest_port);
	udp_header->len = LITTLE_TO_BIG16((uint16_t)(sizeof(udp_header_t) + payload_size));
	memcpy(&udp_header->payload, payload, payload_size);

	// TODO: Doesn't work yet, investigate.
	/* udp_header->checksum = udpsum(udp_header); */
	int ret = send_ipv4_packet(srcip, destip, IPV4_UDP, (char*) udp_header, sizeof(udp_header_t) + payload_size, netif);
	free(udp_header);
	return ret;
}

int udp_bind(const struct sockaddr *addr, socklen_t addrlen, struct inode *vnode)
{
	struct udp_socket *socket = (struct udp_socket*) vnode;
	if(socket->socket.bound)
		return -EINVAL;
	if(!socket->socket.netif)
		socket->socket.netif = netif_choose();
	struct sockaddr_in *in = (struct sockaddr_in *) addr;

	if(socket->socket.netif->udp_ports[in->sin_port])
		return -EADDRINUSE;
	

	if(in->sin_port == 0){}
	/* TODO: Add port allocation */

	/* TODO: This may not be correct behavior. */
	if(in->sin_addr.s_addr == INADDR_ANY)
		in->sin_addr.s_addr = INADDR_LOOPBACK;

	memcpy(&socket->src_addr, addr, sizeof(struct sockaddr));
	socket->socket.netif->udp_ports[in->sin_port] = socket;
	socket->socket.bound = true;
	return 0;
}

int udp_connect(const struct sockaddr *addr, socklen_t addrlen, struct inode *vnode)
{
	struct udp_socket *socket = (struct udp_socket*) vnode;
	memcpy(&socket->dest_addr, addr, sizeof(struct sockaddr));
	if(!socket->socket.netif)
		socket->socket.netif = netif_choose();
	socket->socket.connected = true;
	return 0;
}

ssize_t udp_send(const void *buf, size_t len, int flags, struct inode *vnode)
{
	struct udp_socket *socket = (struct udp_socket*) vnode;
	if(!socket->socket.connected)
		return -ENOTCONN;
	struct sockaddr_in *to = (struct sockaddr_in*) &socket->dest_addr;

	struct sockaddr_in from = {0};
	if(!socket->socket.bound)
		netif_get_ipv4_addr(&from, socket->socket.netif);
	else
		memcpy(&from, &socket->src_addr, sizeof(struct sockaddr));
	if(send_udp_packet((char*) buf, len, from.sin_port, to->sin_port, from.sin_addr.s_addr, to->sin_addr.s_addr, 
		socket->socket.netif) < 0)
		return -errno;
	return len;
}

/* udp_get_queued_packet - Gets either a packet that was queued on recieve or waits for one */
void *udp_get_queued_packet(struct udp_socket *socket)
{
	return NULL;
}

ssize_t udp_recvfrom(void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *slen, struct inode *vnode)
{
	struct udp_socket *socket = (struct udp_socket*) vnode;
	struct sockaddr_in *addr = (struct sockaddr_in *) &socket->src_addr;
	if(!addr->sin_addr.s_addr)
		return -ENOTCONN;
	bool storing_src = src_addr ? true : false;
	(void) storing_src;
	void *kbuf = udp_get_queued_packet(socket);
	if(!kbuf)
		return -ENOMEM;
	return 0;
}

size_t udp_write(size_t offset, size_t sizeofwrite, void* buffer, struct inode* this)
{
	return (size_t) udp_send(buffer, sizeofwrite, 0, this);
}

static struct file_ops udp_ops = 
{
	.bind = udp_bind,
	.connect = udp_connect,
	.send = udp_send,
	.write = udp_write,
	.recvfrom = udp_recvfrom
};

struct socket *udp_create_socket(int type)
{
	struct udp_socket *socket = zalloc(sizeof(struct udp_socket));
	if(!socket)
		return NULL;

	struct inode *vnode = (struct inode*) socket;
	memcpy(&vnode->i_fops, &udp_ops, sizeof(struct file_ops));
	
	vnode->i_type = VFS_TYPE_UNIX_SOCK;
	socket->type = type;
	
	return (struct socket*) socket;
}

int udp_init_netif(struct netif *netif)
{
	/* TODO: Add IPv6 support */
	netif->udp_ports = malloc(65536 * sizeof(struct udp_socket *));
	if(!netif->udp_ports)
		return -1;
	memset(netif->udp_ports, 0, 65536 * sizeof(struct udp_socket *));
	return 0;
}
