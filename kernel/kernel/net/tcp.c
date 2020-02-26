/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>

#include <onyx/tcp.h>
#include <onyx/ip.h>
#include <onyx/byteswap.h>

struct tcp_socket *tcp_get_port(struct netif *nif, in_port_t port)
{
	spin_lock(&nif->tcp_socket_lock_v4);

	list_for_every(&nif->tcp_sockets_v4)
	{
		struct tcp_socket *s = container_of(l, struct tcp_socket, socket_list_head);

		if(s->src_addr.sin_port == port)
		{
			socket_ref(&s->socket);
			spin_unlock(&nif->tcp_socket_lock_v4);
			return s;
		}
	}

	spin_unlock(&nif->tcp_socket_lock_v4);

	return NULL;
}

int tcp_init_netif(struct netif *netif)
{
	INIT_LIST_HEAD(&netif->tcp_sockets_v4);
	INIT_LIST_HEAD(&netif->tcp_sockets_v6);
	return 0;
}

int tcp_bind(const struct sockaddr *addr, socklen_t addrlen, struct inode *vnode)
{
	return -ENXIO;
#if 0
	struct tcp_socket *socket = (struct tcp_socket*) vnode->i_helper;
	if(socket->socket.bound)
		return -EINVAL;
	
	if(!socket->socket.netif)
		socket->socket.netif = netif_choose();

	struct sockaddr_in *in = (struct sockaddr_in *) addr;
	in->sin_port = ntoh16(in->sin_port);

	/* Check if there's any socket bound to this address yet */
	struct tcp_socket *s = tcp_get_port(socket->socket.netif, in->sin_port);
	if(s)
	{
		socket_unref(&s->socket);
		return -EADDRINUSE;
	}
	

	if(in->sin_port == 0){}
	/* TODO: Add port allocation */

	/* TODO: This may not be correct behavior. */
	if(in->sin_addr.s_addr == INADDR_ANY)
		in->sin_addr.s_addr = INADDR_LOOPBACK;

	memcpy(&socket->src_addr, addr, sizeof(struct sockaddr));
	
	tcp_append_socket(socket->socket.netif, socket);
	socket->socket.bound = true;

	return 0;
#endif
}

size_t tcpv4_get_packetlen(void *info, struct packetbuf_proto **next, void **next_info);

struct packetbuf_proto tcpv4_proto =
{
	.name = "tcp",
	.get_len = tcpv4_get_packetlen
};

size_t tcpv4_get_packetlen(void *info, struct packetbuf_proto **next, void **next_info)
{
	struct tcp_socket *socket = info;

	*next = ipv4_get_packetbuf();
	*next_info = socket->socket.netif;

	/* TODO: Handle options */

	return sizeof(struct tcp_header);
}

int tcp_connect(const struct sockaddr *addr, socklen_t addrlen, struct inode *vnode)
{
	return -ENXIO;
#if 0
	struct tcp_socket *socket = (struct tcp_socket*) vnode->i_helper;
	memcpy(&socket->dest_addr, addr, sizeof(struct sockaddr));
	
	if(!socket->socket.bound)
	{
		assert(socket->socket.netif == NULL);
		socket->socket.netif = netif_choose();
		memcpy(&socket->src_addr.sin_addr, &socket->socket.netif->local_ip.sin_addr, sizeof(struct sockaddr_in));
		socket->socket.bound = true;
	}

	struct sockaddr_in *in = (struct sockaddr_in *) addr;
	
	struct packetbuf_info info = {0};
	if(packetbuf_alloc(&info, &tcpv4_proto, socket) < 0)
	{
		packetbuf_free(&info);
		return -ENOMEM;
	}

	struct tcp_header *tcp_packet = (void *)(((char *) info.packet) + packetbuf_get_off(&info));

	tcp_packet->window_size = htons(40000);
	tcp_packet->ack_number = 0;
	tcp_packet->source_port = socket->src_addr.sin_port;
	tcp_packet->sequence_number = 0;
	tcp_packet->data_offset_and_flags = htons(TCP_FLAG_SYN | TCP_FLAG_ACK);
	tcp_packet->dest_port = in->sin_port;
	tcp_packet->urgent_pointer = 0;
	tcp_packet->checksum = 0;
	tcp_packet->checksum = ipsum(tcp_packet, sizeof(tcp_packet));

	int st = ipv4_send_packet(socket->src_addr.sin_addr.s_addr, in->sin_addr.s_addr, IPV4_TCP, &info,
		socket->socket.netif);

	socket->socket.connected = true;
	return 0;
#endif
}

static struct file_ops tcp_ops = 
{
	.bind = tcp_bind,
	.connect = tcp_connect,
};

struct socket *tcp_create_socket(int type)
{
	struct tcp_socket *tcp_sock = zalloc(sizeof(struct tcp_socket));
	if(!tcp_sock)
		return NULL;
	
	tcp_sock->state = TCP_STATE_CLOSED;
	tcp_sock->socket.ops = &tcp_ops;

	return &tcp_sock->socket;
}