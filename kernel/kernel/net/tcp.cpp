/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>
#include <stdio.h>

#include <onyx/random.h>
#include <onyx/net/tcp.h>
#include <onyx/net/ip.h>
#include <onyx/byteswap.h>

extern "C"
int tcp_init_netif(struct netif *netif)
{
	return 0;
}

int tcp_socket::bind(struct sockaddr *addr, socklen_t addrlen)
{
	auto fam = get_proto_fam();

	return fam->bind(addr, addrlen, this);
}

int tcp_bind(struct sockaddr *addr, socklen_t addrlen, struct socket *sock)
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
	*next_info = pkt->nif;

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

	auto socket = inet_resolve_socket<tcp_socket>(ip_header->source_ip,
                      header->source_port, header->dest_port, PROTOCOL_TCP, netif);
	uint16_t tcp_payload_len = static_cast<uint16_t>(size - ip_header_size);

	if(!socket)
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

		socket->append_ack(ack);
	}

out:
	socket_unref(socket);
	
	return st;
}

uint16_t tcpv4_calculate_checksum(tcp_header *header, uint16_t packet_length, uint32_t srcip, uint32_t dstip)
{
	bool padded = packet_length & 1;

	uint32_t proto = ((packet_length + IPV4_TCP) << 8);
	uint16_t buf[2];
	memcpy(&buf, &proto, sizeof(buf));

	uint16_t r = __ipsum_unfolded(&srcip, sizeof(srcip), 0);
	r = __ipsum_unfolded(&dstip, sizeof(dstip), r);
	r = __ipsum_unfolded(buf, sizeof(buf), r);

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

	auto data_off = TCP_MAKE_DATA_OFF(tcp_header_length_to_data_off(header_size));

	/* Assume the max window size as the window size, for now */
	header->window_size = htons(socket->window_size);
	header->source_port = socket->saddr().sin_port;
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
		static_cast<uint16_t>(header_size + payload.size_bytes()), saddr->sin_addr.s_addr, dest.sin_addr.s_addr);

	int st = ip::v4::send_packet(saddr->sin_addr.s_addr, dest.sin_addr.s_addr, IPV4_TCP, &info,
		nif);

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

int tcp_socket::start_handshake(netif *nif, sockaddr_in *from)
{
	tcp_packet first_packet{{}, this, TCP_FLAG_SYN, nif, from};
	tcp_option opt{TCP_OPTION_MSS, 4};

	uint16_t our_mss = nif->mtu - tcp_headers_overhead;
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
	}, st);
	
	if(!ack)
	{
		/* wait_for_ack returns the error code in st (int& error) */
		state = tcp_state::TCP_STATE_CLOSED;
		return st;
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

int tcp_socket::finish_handshake(netif *nif, sockaddr_in *from)
{
	tcp_packet packet{{}, this, TCP_FLAG_ACK, nif, from};
	return packet.send();
}

int tcp_socket::start_connection()
{
	seq_number = arc4random();

	auto fam = get_proto_fam();
	
	/* TODO: This interface is ugly, clunky, and incorrect */
	struct sockaddr src;
	memcpy(&src, &saddr(), sizeof(src));

	auto netif = fam->route(&src, (sockaddr *) &daddr());

	int st = start_handshake(netif, (sockaddr_in *) &src);
	if(st < 0)
		return st;

	st = finish_handshake(netif, (sockaddr_in *) &src);

	state = tcp_state::TCP_STATE_ESTABLISHED;
	
	expected_ack = ack_number;

	return st;
}

int tcp_socket::connect(struct sockaddr *addr, socklen_t addrlen)
{	
	if(!bound)
	{
		auto fam = get_proto_fam();
		int st = fam->bind_any(this);
		if(st < 0)
			return st;
	}

	if(connected)
		return -EISCONN;
	
	if(!validate_sockaddr_len_pair(addr, addrlen))
		return -EINVAL;

	struct sockaddr_in *in = (struct sockaddr_in *) addr;
	(void) in;

	memcpy(&dest_addr, addr, addrlen);
	connected = true;

	return start_connection();
}

int tcp_connect(struct sockaddr *addr, socklen_t addrlen, struct socket *sock)
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

ssize_t tcp_socket::get_max_payload_len(uint16_t tcp_header_len)
{
	struct packetbuf_info in = {};
	
	/* TODO: Rework this - this shouldn't be allowed to fail and we shouldn't
	 * need to allocate memory for this */
	if(packetbuf_alloc(&in, &tcpv4_proto, this) < 0)
		return -ENOMEM;

	auto proto_overhead = in.offsets[in.current_off] + tcp_header_len;

	packetbuf_free(&in);

	return static_cast<ssize_t>(proto_overhead);
}

void tcp_socket::try_to_send()
{
	/* TODO: Implement Nagle's algorithm.
	 * Before we do that, we should probably have retransmission implemented.
	 */
	#if 0
	if(window_size >= mss && current_pos >= mss)
	{
		cul::slice<const uint8_t> data{send_buffer.begin(), mss};
		tcp_packet packet{data, this, TCP_FLAG_ACK | TCP_FLAG_PSH};

		packet.send();

		/* TODO: Implement retries in general? */
		/* TODO: There's lots of room for improvement - maybe a list of buffer
		 * would be a better idea and would avoid this gigantic memcpy we have below
		 * due to vector.
		 */
		auto old_pos = current_pos;
		current_pos -= data.size_bytes();

		if(current_pos != 0)
			memcpy(send_buffer.begin(), send_buffer.end() + 1, old_pos - current_pos);
	}
	else
	#endif
	{
		auto fam = get_proto_fam();
	
		/* TODO: This interface is ugly, clunky, and incorrect */
		struct sockaddr src;
		memcpy(&src, &saddr(), sizeof(src));

		auto netif = fam->route(&src, (sockaddr *) &daddr());
		/* TODO: Support TCP segmentation instead of relying on IPv4 segmentation */
		cul::slice<const uint8_t> data{send_buffer.begin(), current_pos};
		tcp_packet packet{data, this, TCP_FLAG_ACK | TCP_FLAG_PSH, netif, (sockaddr_in *) &src};
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
