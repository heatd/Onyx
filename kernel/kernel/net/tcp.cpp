/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>
#include <stdio.h>

#include <onyx/random.h>
#include <onyx/tcp.h>
#include <onyx/ip.h>
#include <onyx/byteswap.h>

tcp_socket *__tcp_get_port_unlocked(netif *nif, in_port_t port)
{
	MUST_HOLD_LOCK(&nif->tcp_socket_lock_v4);
	list_for_every(&nif->tcp_sockets_v4)
	{
		tcp_socket *s = container_of(l, tcp_socket, socket_list_head);

		if(s->saddr().sin_port == port)
		{
			socket_ref(s);
			return s;
		}
	}

	return NULL;
}

tcp_socket *tcp_get_port(netif *nif, in_port_t port)
{
	spin_lock(&nif->tcp_socket_lock_v4);

	auto ret = __tcp_get_port_unlocked(nif, port);

	spin_unlock(&nif->tcp_socket_lock_v4);

	return ret;
}

extern "C"
int tcp_init_netif(struct netif *netif)
{
	INIT_LIST_HEAD(&netif->tcp_sockets_v4);
	INIT_LIST_HEAD(&netif->tcp_sockets_v6);
	return 0;
}

/* Use linux's ephemeral ports */
static constexpr in_port_t ephemeral_upper_bound = 61000;
static constexpr in_port_t ephemeral_lower_bound = 32768;

void __tcp_append_socket_unlocked(netif *nif, tcp_socket *s)
{
	MUST_HOLD_LOCK(&nif->tcp_socket_lock_v4);
	list_add_tail(&s->socket_list_head, &nif->tcp_sockets_v4);
}

void tcp_append_socket(struct netif *nif, tcp_socket *s)
{
	spin_lock(&nif->tcp_socket_lock_v4);
	__tcp_append_socket_unlocked(nif, s);
	spin_unlock(&nif->tcp_socket_lock_v4);
}

in_port_t tcp_allocate_ephemeral_port(netif *netif)
{
	while(true)
	{
		in_port_t port = htons(static_cast<in_port_t>(arc4random_uniform(
			 ephemeral_upper_bound - ephemeral_lower_bound)) + ephemeral_lower_bound);

		spin_lock(&netif->tcp_socket_lock_v4);

		auto sock = __tcp_get_port_unlocked(netif, port);

		if(!sock)
			return port;
		else
		{
			/* Let's try again, boys */
			spin_unlock(&netif->tcp_socket_lock_v4);
		}
	}

}

int tcp_socket::bind(const struct sockaddr *addr, socklen_t addrlen)
{
	if(bound)
		return -EINVAL;
	
	if(!netif)
		netif = netif_choose();

	struct sockaddr_in *in = (struct sockaddr_in *) addr;
	in->sin_port = ntoh16(in->sin_port);

	/* TODO: This is not correct behavior. We should bind to the netif of the s_addr,
	 * or if INADDR_ANY, bind to every netif
	*/
	if(in->sin_addr.s_addr == INADDR_ANY)
		in->sin_addr.s_addr = htonl(netif->local_ip.sin_addr.s_addr);

	if(in->sin_port != 0)
	{
		/* Check if there's any socket bound to this address yet */
		tcp_socket *s = tcp_get_port(netif, in->sin_port);
		if(s)
		{
			socket_unref(s);
			return -EADDRINUSE;
		}

		spin_lock(&netif->tcp_socket_lock_v4);
	}
	else
	{
		/* Lets try to allocate a new ephemeral port for us */
		auto port = tcp_allocate_ephemeral_port(netif);
		in->sin_port = port;
	}

	/* Note: tcp_socket_lock_v4 needs to be held */

	memcpy(&src_addr, addr, sizeof(struct sockaddr));
	__tcp_append_socket_unlocked(netif, this);
	bound = true;

	spin_unlock(&netif->tcp_socket_lock_v4);

	return 0;
}

int tcp_bind(const struct sockaddr *addr, socklen_t addrlen, struct socket *sock)
{
	tcp_socket *socket = (tcp_socket *) sock;

	return socket->bind(addr, addrlen);
}

size_t tcpv4_get_packetlen(void *info, struct packetbuf_proto **next, void **next_info);

struct packetbuf_proto tcpv4_proto =
{
	.name = "tcp",
	.get_len = tcpv4_get_packetlen
};

size_t tcpv4_get_packetlen(void *info, struct packetbuf_proto **next, void **next_info)
{
	tcp_socket *socket = reinterpret_cast<tcp_socket *>(info);

	*next = ipv4_get_packetbuf();
	*next_info = socket->netif;

	/* TODO: Handle options */

	return sizeof(struct tcp_header);
}

extern "C"
int tcp_handle_packet(struct ip_header *ip_header, size_t size, struct netif *netif)
{
	int st = 0;
	auto ip_header_size = ip_header->ihl * sizeof(uint32_t);
	auto header = reinterpret_cast<tcp_header *>(((uint8_t *) ip_header + ip_header_size));

	auto flags = ntohs(header->data_offset_and_flags);

	auto tcp_port = tcp_get_port(netif, header->dest_port);
	uint16_t tcp_payload_len = static_cast<uint16_t>(size - ip_header_size);

	if(!tcp_port)
	{
		/* No socket bound, bad packet. */
		return 0;
	}

	if(flags & TCP_FLAG_ACK)
	{
		auto new_buf = reinterpret_cast<tcp_header *>(malloc(tcp_payload_len));
		if(!new_buf)
		{
			st = -ENOMEM;
			goto out;
		}

		memcpy(new_buf, header, tcp_payload_len);
	
		tcp_ack *ack = new tcp_ack(new_buf, tcp_payload_len);
		if(!ack)
		{
			free((void *) new_buf);
			goto out;
		}

		tcp_port->append_ack(ack);
	}

out:
	socket_unref(tcp_port);
	
	return st;
}

uint16_t tcpv4_calculate_checksum(tcp_header *header, uint16_t packet_length, uint32_t srcip, uint32_t dstip)
{
	uint32_t proto = ((packet_length + IPV4_TCP) << 8);
	
	uint16_t r = __ipsum_unfolded(&srcip, sizeof(srcip), 0);
	r = __ipsum_unfolded(&dstip, sizeof(dstip), r);
	r = __ipsum_unfolded(&proto, sizeof(proto), r);
	
	r = __ipsum_unfolded(header, packet_length, r);

	return ipsum_fold(r);
}

constexpr inline uint16_t tcp_header_length_to_data_off(uint16_t len)
{
	return len / sizeof(uint32_t);
}

#define TCP_MAKE_DATA_OFF(off)		(off << TCP_DATA_OFFSET_SHIFT)

int tcp_socket::send_syn_ack(uint16_t flags)
{
	struct packetbuf_info info = {0};
	if(packetbuf_alloc(&info, &tcpv4_proto, this) < 0)
	{
		packetbuf_free(&info);
		return -ENOMEM;
	}

	struct tcp_header *tcp_packet = (tcp_header *)(((char *) info.packet) + packetbuf_get_off(&info));

	memset(tcp_packet, 0, sizeof(tcp_header));
	
	auto &dest = daddr();
	auto &src = saddr();

	auto data_off = TCP_MAKE_DATA_OFF(tcp_header_length_to_data_off(sizeof(tcp_header)));

	/* Assume the max window size as the window size, for now */
	tcp_packet->window_size = htons(UINT16_MAX);
	tcp_packet->source_port = src.sin_port;
	tcp_packet->sequence_number = htonl(seq_number);
	tcp_packet->data_offset_and_flags = htons(data_off | flags);
	tcp_packet->dest_port = dest.sin_port;
	tcp_packet->urgent_pointer = 0;
	
	if(flags & TCP_FLAG_ACK)
		tcp_packet->ack_number = htonl(ack_number + 1);
	else
		tcp_packet->ack_number = 0;

	tcp_packet->checksum = tcpv4_calculate_checksum(tcp_packet,
		sizeof(tcp_header), src.sin_addr.s_addr, dest.sin_addr.s_addr);

	int st = ipv4_send_packet(src.sin_addr.s_addr, dest.sin_addr.s_addr, IPV4_TCP, &info,
		netif);
	
	state = tcp_state::TCP_STATE_SYN_SENT;

	packetbuf_free(&info);

	if(st < 0)
	{
		state = tcp_state::TCP_STATE_CLOSED;
		return st;
	}

	return 0;
}

int tcp_socket::start_connection()
{
	seq_number = arc4random();

	int st = send_syn_ack(TCP_FLAG_SYN);
	
	if(st < 0)
		return st;

	auto ack = wait_for_ack([this](const tcp_ack *ack) -> bool
	{
		auto header = ack->get_packet();
		if(ntohl(header->ack_number) != (seq_number + 1))
			return false;

		auto flags = ntohs(header->data_offset_and_flags);

		if((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) != (TCP_FLAG_ACK | TCP_FLAG_SYN))
			return false;

		return true;
	});
	
	if(!ack)
	{
		return -ETIMEDOUT;
	}
	
	auto packet = ack->get_packet();

	ack_number = ntohl(packet->sequence_number);
	seq_number++;

	st = send_syn_ack(TCP_FLAG_ACK);
	
	delete ack;

	return st;
}

int tcp_socket::connect(const struct sockaddr *addr, socklen_t addrlen)
{	
	if(!bound)
	{
		/* TODO: We probably need locks here.
		 * Also, maybe sockets shouldn't be such in bed with vfs code.
		 */

		sockaddr_in bind_addr = {};
		bind_addr.sin_family = AF_INET;
		bind_addr.sin_addr.s_addr = INADDR_ANY;
		bind_addr.sin_port = 0;
	
		bind((const sockaddr *) &bind_addr, sizeof(bind_addr));
	}

	if(connected)
		return -EISCONN;

	struct sockaddr_in *in = (struct sockaddr_in *) addr;
	(void) in;

	memcpy(&dest_addr, addr, addrlen);
	connected = true;

	return start_connection();
}

int tcp_connect(const struct sockaddr *addr, socklen_t addrlen, struct socket *sock)
{
	tcp_socket *socket = (tcp_socket*) sock;
	return socket->connect(addr, addrlen);
}

ssize_t tcp_socket::sendto(const void *buf, size_t len, int flags)
{
	mutex_lock(&send_buffer_lock);

	if(send_buffer.buf_size() < current_pos + len)
	{
		if(!send_buffer.alloc_buf(current_pos + len))
		{
			mutex_unlock(&send_buffer_lock);
			return -ENOMEM;
		}
	}

	mutex_unlock(&send_buffer_lock);

	return 0;
}

ssize_t tcp_sendto(const void *buf, size_t len, int flags, struct sockaddr *addr,
             socklen_t alen, struct socket *sock)
{
	/* TODO: Do we need to handle addr != NULL */
	tcp_socket *socket = (tcp_socket*) sock;
	return socket->sendto(buf, len, flags);
}

static struct sock_ops tcp_ops = 
{
	.bind = tcp_bind,
	.connect = tcp_connect,
	.sendto = tcp_sendto
};

extern "C"
struct socket *tcp_create_socket(int type)
{
	tcp_socket *tcp_sock = new tcp_socket();
	if(!tcp_sock)
		return NULL;

	tcp_sock->s_ops = &tcp_ops;

	return tcp_sock;
}