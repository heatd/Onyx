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

constexpr inline uint16_t tcp_header_length_to_data_off(uint16_t len)
{
	return len / sizeof(uint32_t);
}

constexpr inline uint16_t tcp_header_data_off_to_length(uint16_t len)
{
	return len * sizeof(uint32_t);
}

#define TCP_MAKE_DATA_OFF(off)		(off << TCP_DATA_OFFSET_SHIFT)
#define TCP_GET_DATA_OFF(off)		(off >> TCP_DATA_OFFSET_SHIFT)

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

int tcp_socket::handle_packet(const tcp_socket::packet_handling_data& data)
{
	auto data_off = TCP_GET_DATA_OFF(ntohs(data.header->data_offset_and_flags));
	uint16_t header_size = tcp_header_data_off_to_length(data_off);
	auto seq_number = ntohl(data.header->sequence_number);

	if(data.tcp_segment_size < header_size)
		return -1;
#if 0
	printk("segment size: %u\n", data.tcp_segment_size);
	printk("header size: %u\n", header_size);
	printk("ack number %u\n", ack_number);
#endif

	uint16_t data_size = data.tcp_segment_size - header_size;
	cul::slice<uint8_t> buf{(uint8_t *) data.header + header_size, data_size}; 

	auto flags = htons(data.header->data_offset_and_flags);

	/* TODO: Send RST on bad packets */
	if(flags & TCP_FLAG_SYN)
	{
		if(state != tcp_state::TCP_STATE_SYN_SENT)
			return 0;
		window_size = ntohs(data.header->window_size) << window_size_shift;

		if(!parse_options(data.header))
		{
			/* Invalid packet */
			state = tcp_state::TCP_STATE_CLOSED;
			return -EIO;
		}
	}

	if(flags & TCP_FLAG_ACK)
	{
		if(state == tcp_state::TCP_STATE_LISTEN || state == tcp_state::TCP_STATE_CLOSED)
			return 0;
	
		/* Filter out out-of-order packets by checking the seq number */
		if(!(flags & TCP_FLAG_SYN) && seq_number != ack_number)
		{
#if 0
			printk("seq number %u - ack %u\n", seq_number, ack_number);
#endif
			return -1;
		}

		auto ack = ntohl(data.header->ack_number);

		scoped_lock guard{&pending_out_packets_lock};

		bool was_acked = false;

		list_for_every_safe(&pending_out_packets)
		{
			auto pkt = list_head_cpp<tcp_packet>::self_from_list_head(l);
			if(!pkt->ack_for_packet(last_ack_number, ack))
				continue;
#if 0
			printk("Packet: %p\n", pkt);
#endif
			was_acked = true;
			pkt->acked = true;
			wait_queue_wake_all(&pkt->ack_wq);

			list_remove(&pkt->pending_packet_list_node);
			
			/* Unref *must* be the last thing we do */
			pkt->unref();
		}

		guard.unlock();

		(void) was_acked;

		last_ack_number = ack;
		/* ack_number holds the other side of the connection's sequence number */
		{
			/* ack_number holds the other side of the connection's sequence number */
			auto starting_seq_number = ntohl(data.header->sequence_number);
			uint32_t seqs = data_size;
			if(flags & TCP_FLAG_SYN)
				seqs++;
			if(flags & TCP_FLAG_FIN)
				seqs++;

#if 0
			printk("These seqs: %u\n", seqs);
#endif
			ack_number = starting_seq_number + seqs;
		}
	}

#if 0
	printk("next ack number %u\n", ack_number);
#endif

	if(data_size || flags & TCP_FLAG_FIN)
	{
		recv_packet *p = new recv_packet();
		if(!p)
			return -1;
		
		p->addr_len = sizeof(sockaddr_in);
		memcpy(&p->src_addr, data.src_addr, sizeof(sockaddr_in));
		p->payload = memdup(buf.data(), buf.size_bytes());
		if(!p->payload)
		{
			delete p;
			return -1;
		}

		p->size = buf.size_bytes();

		in_band_queue.add_packet(p);

		struct sockaddr src;
		memcpy(&src, &saddr(), sizeof(src));
		auto fam = get_proto_fam();

		auto netif = fam->route(&src, (sockaddr *) &daddr());
	
		tcp_packet pkt{{}, this, TCP_FLAG_ACK, netif, (sockaddr_in *) &src};
		pkt.send();
	}

	return 0;
}

extern "C"
int tcp_handle_packet(struct ip_header *ip_header, size_t size, struct netif *netif)
{
	int st = 0;
	auto ip_header_size = ip_header->ihl * sizeof(uint32_t);
	auto header = reinterpret_cast<tcp_header *>(((uint8_t *) ip_header + ip_header_size));

	if(!validate_tcp_packet(header, size))
		return 0;

	auto socket = inet_resolve_socket<tcp_socket>(ip_header->source_ip,
                      header->source_port, header->dest_port, IPPROTO_TCP, netif);
	uint16_t tcp_payload_len = static_cast<uint16_t>(size - ip_header_size);

	if(!socket)
	{
		/* No socket bound, bad packet. */
		return 0;
	}

	sockaddr_in_both both;
	ipv4_to_sockaddr(ip_header->source_ip, header->source_port, both.in4);

	const tcp_socket::packet_handling_data handle_data{header, tcp_payload_len, &both}; 

	st = socket->handle_packet(handle_data);

	socket->unref();
	
	return st;
}

uint16_t tcpv4_calculate_checksum(tcp_header *header, uint16_t packet_length, uint32_t srcip, uint32_t dstip)
{
	bool padded = packet_length & 1;

	uint32_t proto = ((packet_length + IPV4_TCP) << 8);
	uint16_t buf[2];
	memcpy(&buf, &proto, sizeof(buf));

	auto r = __ipsum_unfolded(&srcip, sizeof(srcip), 0);
	r = __ipsum_unfolded(&dstip, sizeof(dstip), r);
	r = __ipsum_unfolded(buf, sizeof(buf), r);

	r = __ipsum_unfolded(header, padded ? packet_length + 1 : packet_length, r);

	return ipsum_fold(r);
}

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

	packetbuf_inited = true;

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
		header->ack_number = htonl(socket->acknowledge_nr());
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

	if(should_wait_for_ack())
		socket->append_pending_out(this);

	starting_seq_number = socket->sequence_nr();
	uint32_t seqs = payload.size_bytes();
	if(flags & TCP_FLAG_SYN)
		seqs++;

	socket->sequence_nr() += seqs;

	int st = ip::v4::send_packet(saddr->sin_addr.s_addr, dest.sin_addr.s_addr, IPV4_TCP, &info,
		nif);

	if(padded) info.length++;

	if(st < 0)
	{
		socket->remove_pending_out(this);
		return st;
	}

	return 0;
}

int tcp_packet::wait_for_ack()
{
	return wait_for_event_interruptible(&ack_wq, acked);
}

int tcp_packet::wait_for_ack_timeout(hrtime_t _timeout)
{
	return wait_for_event_timeout_interruptible(&ack_wq, acked, _timeout);
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
	first_packet.set_packet_flags(TCP_PACKET_FLAG_ON_STACK | TCP_PACKET_FLAG_WANTS_ACK_HEADER);

	tcp_option opt{TCP_OPTION_MSS, 4};

	uint16_t our_mss = nif->mtu - tcp_headers_overhead;
	opt.data.mss = htons(our_mss);

	first_packet.append_option(&opt);

	int st = first_packet.send();

	if(st < 0)
		return st;

	state = tcp_state::TCP_STATE_SYN_SENT;

	/* TODO: Timeouts */
	st = first_packet.wait_for_ack();

#if 0
	printk("ack received\n");
#endif

	if(st < 0)
	{
		/* wait_for_ack returns the error code in st */
		state = tcp_state::TCP_STATE_CLOSED;
		return st;
	}

	state = tcp_state::TCP_STATE_SYN_receiveD;
	
#if 0
	/* TODO: Add this */
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
#endif

	return 0;
}

int tcp_socket::finish_handshake(netif *nif, sockaddr_in *from)
{
	tcp_packet packet{{}, this, TCP_FLAG_ACK, nif, from};
	packet.set_packet_flags(TCP_PACKET_FLAG_ON_STACK);

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
	
		/* TODO: This interface is ugly, clunky, and incorrect for ipv6.
		 * We should widen use of sockaddr_in_both */
		struct sockaddr src;
		memcpy(&src, &saddr(), sizeof(src));

		auto netif = fam->route(&src, (sockaddr *) &daddr());
		/* TODO: Support TCP segmentation instead of relying on IPv4 segmentation */
		cul::slice<const uint8_t> data{send_buffer.begin(), current_pos};
		tcp_packet *packet = new tcp_packet{data, this, TCP_FLAG_ACK | TCP_FLAG_PSH, netif, (sockaddr_in *) &src};
		if(!packet)
			return;
		
		/* TODO: Return errors from this */
		auto st = packet->send();
		if(st < 0)
		{
			return;
		}

		packet->unref();
	}
}

ssize_t tcp_socket::sendto(const void *buf, size_t len, int flags, sockaddr *addr, socklen_t addrlen)
{
	if(addr)
		return -EISCONN;

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

void tcp_socket::append_pending_out(tcp_packet *pckt)
{
	scoped_lock<spinlock> guard{&pending_out_packets_lock};
	list_add_tail(&pckt->pending_packet_list_node, &pending_out_packets);
	
	/* Don't forget to ref the packet! */
	pckt->ref();
}

void tcp_socket::remove_pending_out(tcp_packet *pkt)
{
	scoped_lock guard{&pending_out_packets_lock};

	list_remove(&pkt->pending_packet_list_node);
	
	/* And also don't forget to unref it back! */
	pkt->unref();
}

int tcp_socket::setsockopt(int level, int opt, const void *optval, socklen_t optlen)
{
	if(level == SOL_SOCKET)
		return setsockopt_socket_level(opt, optval, optlen);
	
	if(is_inet_level(level))
		return setsockopt_inet(level, opt, optval, optlen);

	return -ENOPROTOOPT;
}

int tcp_socket::getsockopt(int level, int opt, void *optval, socklen_t *optlen)
{
	if(level == SOL_SOCKET)
		return getsockopt_socket_level(opt, optval, optlen);
	return -ENOPROTOOPT;
}

extern "C"
struct socket *tcp_create_socket(int type)
{
	return new tcp_socket();
}
