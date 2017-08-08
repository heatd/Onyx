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

#include <kernel/dev.h>
#include <kernel/ip.h>
#include <kernel/udp.h>
#include <kernel/netif.h>
#include <kernel/compiler.h>

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
int udp_bind(const struct sockaddr *addr, socklen_t addrlen, vfsnode_t *vnode)
{
	udp_socket_t *socket = (udp_socket_t*) vnode;
	if(socket->socket.bound)
		return -EINVAL;
	if(!socket->socket.netif)
		socket->socket.netif = netif_choose();
	struct sockaddr_in *in = (struct sockaddr_in *) addr;
	if(socket->socket.netif->udp_ports[in->sin_port])
		return -EADDRINUSE;
	memcpy(&socket->src_addr, addr, sizeof(struct sockaddr));
	socket->socket.netif->udp_ports[in->sin_port] = socket;
	socket->socket.bound = true;
	return 0;
}
int udp_connect(const struct sockaddr *addr, socklen_t addrlen, vfsnode_t *vnode)
{
	udp_socket_t *socket = (udp_socket_t*) vnode;
	memcpy(&socket->dest_addr, addr, sizeof(struct sockaddr));
	if(!socket->socket.netif)
		socket->socket.netif = netif_choose();
	socket->socket.connected = true;
	return 0;
}
ssize_t udp_send(const void *buf, size_t len, int flags, vfsnode_t *vnode)
{
	udp_socket_t *socket = (udp_socket_t*) vnode;
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
ssize_t udp_recvfrom(void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *slen, vfsnode_t *vnode)
{
	//udp_socket_t *socket = (udp_socket_t*) vnode;
	bool storing_src = src_addr ? true : false;
	if(storing_src)
	{
		if(vmm_check_pointer(src_addr, sizeof(struct sockaddr)) < 0)
			return -EFAULT;
		if(vmm_check_pointer(slen, sizeof(socklen_t)) < 0)
			return -EFAULT;
	}
	while(1);
}
size_t udp_write(size_t offset, size_t sizeofwrite, void* buffer, vfsnode_t* this)
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
socket_t *udp_create_socket(int type)
{
	udp_socket_t *socket = malloc(sizeof(udp_socket_t));
	if(!socket)
		return NULL;
	memset(socket, 0, sizeof(udp_socket_t));
	vfsnode_t *vnode = (vfsnode_t*) socket;
	memcpy(&vnode->fops, &udp_ops, sizeof(struct file_ops));
	vnode->type = VFS_TYPE_UNIX_SOCK;
	socket->type = type;
	return (socket_t*) socket;
}
int udp_init_netif(struct netif *netif)
{
	/* TODO: Add IPv6 support */
	netif->udp_ports = malloc(65536 * sizeof(udp_socket_t*));
	if(!netif->udp_ports)
		return -1;
	memset(netif->udp_ports, 0, 65536 * sizeof(udp_socket_t*));
	return 0;
}
