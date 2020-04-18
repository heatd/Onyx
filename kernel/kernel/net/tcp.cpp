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
		in->sin_addr.s_addr = netif->local_ip.sin_addr.s_addr;

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
	tcp_packet *pkt = reinterpret_cast<tcp_packet *>(info);

	*next = ipv4_get_packetbuf();
	*next_info = pkt->get_socket()->netif;

	return sizeof(struct tcp_header) + pkt->options_length();
}

bool validate_tcp_packet(const tcp_header *header, size_t size)
{
	if(sizeof(tcp_header) > size)
		return false;

	auto flags = ntohs(header->data_offset_and_flags);

	uint16_t data_off = flags >> TCP_DATA_OFFSET_SHIFT;
	size_t off_bytes = data_off * sizeof(uint32_t);

	if(off_bytes > size)
		return false;

	return true;
}

extern "C"
int tcp_handle_packet(struct ip_header *ip_header, size_t size, struct netif *netif)
{
	int st = 0;
	auto ip_header_size = ip_header->ihl * sizeof(uint32_t);
	auto header = reinterpret_cast<tcp_header *>(((uint8_t *) ip_header + ip_header_size));

	if(!validate_tcp_packet(header, size))
		return 0;

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
	bool padded = packet_length & 1;

	uint32_t proto = ((packet_length + IPV4_TCP) << 8);

	uint16_t r = __ipsum_unfolded(&srcip, sizeof(srcip), 0);
	r = __ipsum_unfolded(&dstip, sizeof(dstip), r);
	r = __ipsum_unfolded(&proto, sizeof(proto), r);

	r = __ipsum_unfolded(header, padded ? packet_length + 1 : packet_length, r);

	return ipsum_fold(r);
}

constexpr inline uint16_t tcp_header_length_to_data_off(uint16_t len)
{
	return len / sizeof(uint32_t);
}

#define TCP_MAKE_DATA_OFF(off)		(off << TCP_DATA_OFFSET_SHIFT)

uint16_t tcp_packet::options_length() const
{
	uint16_t len = 0;
	list_for_every_safe(&option_list)
	{
		tcp_option *opt = container_of(l, tcp_option, list_node);
		len += opt->length;
	}

	/* TCP options have padding to make sure it ends on a 32-bit boundary */
	if(len & (4 - 1))
		len = ALIGN_TO(len, 4);

	return len;
}

void tcp_packet::put_options(char *opts)
{
	list_for_every(&option_list)
	{
		tcp_option *opt = container_of(l, tcp_option, list_node);

		opts[0] = opt->kind;
		opts[1] = opt->length;
		/* Take off 2 bytes to account for the overhead of kind and length */
		memcpy(&opts[2], &opt->data, opt->length - 2);
		opts += opt->length;
	}
}

int tcp_packet::send()
{
	struct packetbuf_info info = {0};
	info.length = payload.size_bytes();
	bool padded = false;

	if(info.length & 1)
	{
		padded = true;
		info.length++;
	}

	if(packetbuf_alloc(&info, &tcpv4_proto, this) < 0)
	{
		packetbuf_free(&info);
		return -ENOMEM;
	}

	uint16_t options_len = options_length();
	auto header_size = sizeof(tcp_header) + options_len;

	struct tcp_header *header = (tcp_header *)(((char *) info.packet) + packetbuf_get_off(&info));

	memset(header, 0, header_size);

	auto &dest = socket->daddr();
	auto &src = socket->saddr();

	auto data_off = TCP_MAKE_DATA_OFF(tcp_header_length_to_data_off(header_size));

	/* Assume the max window size as the window size, for now */
	header->window_size = htons(socket->window_size);
	header->source_port = src.sin_port;
	header->sequence_number = htonl(socket->sequence_nr());
	header->data_offset_and_flags = htons(data_off | flags);
	header->dest_port = dest.sin_port;
	header->urgent_pointer = 0;

	if(flags & TCP_FLAG_ACK)
		header->ack_number = htonl(socket->acknowledge_nr() + 1);
	else
		header->ack_number = 0;

	put_options(reinterpret_cast<char *>(header + 1));

	char *payload_ptr = reinterpret_cast<char *>(header) + header_size;

	if(payload.size_bytes() != 0)
		memcpy(payload_ptr, payload.data(), payload.size_bytes());

	if(padded)
	{
		payload_ptr[payload.size_bytes()] = 0;
		info.length--;
	}

	header->checksum = tcpv4_calculate_checksum(header,
		header_size + payload.size_bytes(), src.sin_addr.s_addr, dest.sin_addr.s_addr);

	int st = ipv4_send_packet(src.sin_addr.s_addr, dest.sin_addr.s_addr, IPV4_TCP, &info,
		socket->netif);

	if(padded) info.length++;

	packetbuf_free(&info);

	if(st < 0)
	{
		return st;
	}

	return 0;
}

static constexpr uint16_t min_header_size = sizeof(tcp_header);

bool tcp_socket::parse_options(tcp_header *packet)
{
	auto flags = ntohs(packet->data_offset_and_flags);

	bool syn_set = flags & TCP_FLAG_SYN;
	(void) syn_set;

	uint16_t data_off = flags >> TCP_DATA_OFFSET_SHIFT;

	if(data_off == tcp_header_length_to_data_off(min_header_size))
		return true;

	auto data_off_bytes = data_off * sizeof(uint32_t);
	
	uint8_t *options = reinterpret_cast<uint8_t *>(packet + 1);
	uint8_t *end = options + (data_off_bytes - min_header_size);

	while(options != end)
	{
		uint8_t opt_byte = *options;

		/* The layout of TCP options is [byte 0 - option kind]
		 * [byte 1 - option length ] [byte 2...length - option data]
		 */

		if(opt_byte == TCP_OPTION_END_OF_OPTIONS)
			break;

		if(opt_byte == TCP_OPTION_NOP)
		{
			options++;
			continue;
		}
		
		uint8_t length = *(options + 1);

		switch(opt_byte)
		{
			case TCP_OPTION_MSS:
				if(!syn_set)
					return false;

				mss = *(uint16_t *)(options + 2);
				mss = ntohs(mss);
				break;
			case TCP_OPTION_WINDOW_SCALE:
				if(!syn_set)
					return false;

				uint8_t wss = *(options + 2);
				window_size_shift = wss;
				break;
		}


		options += length;
	}

	return true;
}

/* TODO: This doesn't apply to IPv6 */
constexpr uint16_t tcp_headers_overhead = sizeof(struct tcp_header) +
	sizeof(ethernet_header_t) + IPV4_MIN_HEADER_LEN;

int tcp_socket::start_handshake()
{
	tcp_packet first_packet{{}, this, TCP_FLAG_SYN};
	tcp_option opt{TCP_OPTION_MSS, 4};
	uint16_t our_mss = netif->mtu - tcp_headers_overhead;
	opt.data.mss = htons(our_mss);

	first_packet.append_option(&opt);

	int st = first_packet.send();

	if(st < 0)
		return st;

	state = tcp_state::TCP_STATE_SYN_SENT;

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
		state = tcp_state::TCP_STATE_CLOSED;
		return -ETIMEDOUT;
	}

	state = tcp_state::TCP_STATE_SYN_RECIEVED;
	
	auto packet = ack->get_packet();

	ack_number = ntohl(packet->sequence_number);
	seq_number++;
	window_size = ntohs(packet->window_size) << window_size_shift;

	if(!parse_options(packet))
	{
		delete ack;
		/* Invalid packet */
		state = tcp_state::TCP_STATE_CLOSED;
		return -EIO;
	}

	delete ack;

	return 0;
}

int tcp_socket::finish_handshake()
{
	tcp_packet packet{{}, this, TCP_FLAG_ACK};
	return packet.send();
}

int tcp_socket::start_connection()
{
	seq_number = arc4random();

	int st = start_handshake();
	if(st < 0)
		return st;

	st = finish_handshake();

	state = tcp_state::TCP_STATE_ESTABLISHED;
	
	expected_ack = ack_number;

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

ssize_t tcp_socket::queue_data(const void *user_buf, size_t len)
{
	if(current_pos + len > send_buffer.buf_size())
	{
		if(!send_buffer.alloc_buf(current_pos + len))
		{
			return -EINVAL;
		}
	}


	uint8_t *ptr = send_buffer.get_buf() + current_pos;

	if(copy_from_user(ptr, user_buf, len) < 0)
		return -EFAULT;
	current_pos += len;

	return 0;
}

void tcp_socket::try_to_send()
{
	if(window_size >= mss && current_pos >= mss)
	{
		cul::slice<const uint8_t> data{send_buffer.begin(), mss};
		tcp_packet packet{data, this, TCP_FLAG_ACK | TCP_FLAG_PSH};

		packet.send();

		/* TODO: Retry? */
		auto old_pos = current_pos;
		current_pos -= data.size_bytes();

		if(current_pos != 0)
			memcpy(send_buffer.begin(), send_buffer.end() + 1, old_pos - current_pos);
	}
	else
	{
		/* TODO: Wait for ack */
		cul::slice<const uint8_t> data{send_buffer.begin(), current_pos};
		tcp_packet packet{data, this, TCP_FLAG_ACK | TCP_FLAG_PSH};
		packet.send();
	}
}

ssize_t tcp_socket::sendto(const void *buf, size_t len, int flags)
{
	if(len > UINT16_MAX)
		return -EINVAL;

	mutex_lock(&send_lock);

	auto st = queue_data(buf, len);
	if(st < 0)
	{
		mutex_unlock(&send_lock);
		return st;
	}

	try_to_send();

	mutex_unlock(&send_lock);

	return len;
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
