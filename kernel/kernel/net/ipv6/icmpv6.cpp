/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <errno.h>

#include <onyx/cred.h>

#include <onyx/scoped_lock.h>
#include <onyx/spinlock.h>
#include <onyx/poll.h>

#include <onyx/net/inet_csum.h>
#include <onyx/net/ipv6.h>
#include <onyx/net/ip.h>
#include <onyx/packetbuf.h>
#include <onyx/net/icmpv6.h>
#include <onyx/net/ndp.h>

namespace icmpv6
{

socket_table icmp_table;
const inet_proto icmp6_proto{"icmp6", &icmp_table};

#define ICMPV6_PACKETBUF_HEADER_SPACE PACKET_MAX_HEAD_LENGTH + sizeof(ip6hdr) + sizeof(icmpv6_header)

ref_guard<packetbuf> allocate_icmp_response_packet(unsigned int extra_size = 0)
{
	auto buf = make_refc<packetbuf>();
	if(!buf)
		return {};
	
	if(!buf->allocate_space(ICMPV6_PACKETBUF_HEADER_SPACE + extra_size))
		return {};
	
	buf->reserve_headers(ICMPV6_PACKETBUF_HEADER_SPACE);

	return buf;
}

inetsum_t calculate_icmpv6_header_csum(const in6_addr& src, const in6_addr& dst, uint32_t header_length)
{
	auto csum = __ipsum_unfolded(&src, sizeof(src), 0);
	csum = __ipsum_unfolded(&dst, sizeof(dst), csum);

	uint32_t reversed_len = htonl(header_length);
	uint32_t next_header = htonl(IPPROTO_ICMPV6);
	csum = __ipsum_unfolded(&reversed_len, sizeof(reversed_len), csum);
	return __ipsum_unfolded(&next_header, sizeof(next_header), csum);
}

int send_packet(const send_data& data, cul::slice<unsigned char> packet_data)
{
	auto buf = make_refc<packetbuf>();
	if(!buf)
		return -ENOMEM;

	if(!buf->allocate_space(ICMPV6_PACKETBUF_HEADER_SPACE + packet_data.size_bytes()))
		return -ENOMEM;

	buf->reserve_headers(ICMPV6_PACKETBUF_HEADER_SPACE);
	
	auto hdr = (icmpv6_header *) buf->push_header(sizeof(icmpv6_header));
	hdr->type = data.type;
	hdr->code = data.code;
	hdr->data = data.data;
	hdr->checksum = 0;

	if(packet_data.size_bytes())
	{
		auto ptr = buf->put(packet_data.size_bytes());
		memcpy(ptr, packet_data.data(), packet_data.size_bytes());
	}

	uint32_t length = packet_data.size_bytes() + sizeof(icmpv6_header);

	auto csum = calculate_icmpv6_header_csum(data.route.src_addr.in6, data.route.dst_addr.in6, length);
	csum = __ipsum_unfolded(hdr, length, csum);

	hdr->checksum = ipsum_fold(csum);

	iflow flow{data.route, IPPROTO_ICMPV6, true};
	flow.ttl = 255;
	return ip::v6::send_packet(flow, buf.get());
}

int handle_packet(netif *nif, packetbuf *buf)
{
	if(buf->length() < min_icmp6_size())
		return -EINVAL;

	ip6hdr *iphdr = (ip6hdr *) buf->net_header;

	auto header = (icmpv6_header *) buf->data;
	auto header_length = buf->length();

	(void) header_length;

	switch(header->type)
	{
		case ICMPV6_ECHO_REQUEST:
			//send_echo_reply(iphdr, header, header_length, nif);
			break;
		case ICMPV6_NEIGHBOUR_ADVERT:
		case ICMPV6_NEIGHBOUR_SOLICIT:
			ndp_handle_packet(nif, buf);
			break;
	}

	icmp6_socket *socket = nullptr;
	unsigned int inst = 0;

	do
	{
		socket = inet6_resolve_socket<icmp6_socket>(iphdr->src_addr, 0, 0, IPPROTO_ICMPV6,
		                                          nif, true, &icmp6_proto, inst);
		if(!socket)
			break;

		inst++;

		if(socket->match_filter(header))
		{
			auto pbf = packetbuf_clone(buf);
			/* Out of memory, give up trying to clone this packet to other sockets */
			if(!pbf)
				break;

			socket->append_inet_rx_pbuf(pbf);
			pbf->unref();
		}
	
	} while(socket != nullptr);

	return 0;
}


int icmp6_socket::bind(sockaddr *addr, socklen_t len)
{
	if(!validate_sockaddr_len_pair(addr, len))
		return -EINVAL;

	auto proto = get_proto_fam();
	return proto->bind(addr, len, this);
}

int icmp6_socket::connect(sockaddr *addr, socklen_t len)
{
	if(!validate_sockaddr_len_pair(addr, len))
		return -EINVAL;
	
	auto res = sockaddr_to_isa(addr);
	dest_addr = res.first;

	bool on_ipv4_mode = res.second == AF_INET && domain == AF_INET6;

	/* No hybrid-stackness with ICMPv6 */
	if(on_ipv4_mode)
		return -EINVAL;

	if(!bound)
	{
		auto fam = get_proto_fam();
		int st = fam->bind_any(this);
		if(st < 0)
			return st;
	}

	ipv4_on_inet6 = false;

	connected = true;
	
	auto route_result = get_proto_fam()->route(src_addr, dest_addr, res.second);
	
	/* If we've got an error, ignore it. Is this correct/sane behavior? */
	if(route_result.has_error())
	{
		connected = false;
		return 0;
	}

	route_cache = route_result.value();
	route_cache_valid = 1;

	return 0;
}

bool is_security_sensitive_icmp_packet(icmpv6_header *header)
{
	return header->type != ICMPV6_ECHO_REQUEST;
}

ssize_t icmp6_socket::sendmsg(const struct msghdr *msg, int flags)
{
	cul::vector<ip_option> options;

	auto iovlen = iovec_count_length(msg->msg_iov, msg->msg_iovlen);
	if(iovlen < 0)
		return iovlen;

	if(iovlen < min_icmp6_size())
		return -EINVAL;

	if(iovlen > UINT16_MAX)
		return -EINVAL;
	
	auto sa_dst_addr = (sockaddr *) msg->msg_name; 
	
	auto to = dest_addr;

	if(msg->msg_name)
	{
		if(!validate_sockaddr_len_pair(sa_dst_addr, msg->msg_namelen))
			return -EINVAL;

		auto res = sockaddr_to_isa(sa_dst_addr);
		to = res.first;
	}
	else
	{
		if(!connected)
			return -ENOTCONN;
	}

	if(!bound)
	{
		auto fam = get_proto_fam();
		int st = fam->bind_any(this);
		if(st < 0)
			return st;
	}
	
	unsigned int extra_size = iovlen - min_icmp6_size();

	auto packet = allocate_icmp_response_packet(extra_size);
	if(!packet)
		return -ENOBUFS;

	inet_route rt;

	if(connected && route_cache_valid)
	{
		rt = route_cache;
	}
	else
	{
		auto proto = get_proto_fam();
		auto st = proto->route(src_addr, to, AF_INET6);
		if(st.has_error())
			return st.error();
		
		rt = st.value();
	}

	auto hdr = (icmpv6_header *) packet->push_header(min_icmp6_size());
	packet->put(extra_size);
	auto p = (unsigned char *) hdr;

	for(int i = 0; i < msg->msg_iovlen; i++)
	{
		auto &vec = msg->msg_iov[i];

		if(copy_from_user(p, vec.iov_base, vec.iov_len) < 0)
			return -EFAULT;
		
		p += vec.iov_len;
	}

	if(is_security_sensitive_icmp_packet(hdr) && !is_root_user())
		return -EPERM;

	hdr->checksum = 0;

	auto csum = calculate_icmpv6_header_csum(rt.src_addr.in6, rt.dst_addr.in6, iovlen);
	csum = __ipsum_unfolded(hdr, iovlen, csum);

	hdr->checksum = ipsum_fold(csum);

	iflow flow{rt, IPPROTO_ICMPV6, true};

	flow.ttl = ttl;

	/* TODO: Huge hack. */
	if(hdr->type == ICMPV6_MLDV2_REPORT_MSG)
	{
		struct ip_option router_alert;
		router_alert.option = IPV6_EXT_HEADER_HOP_BY_HOP;

		/* Zeroing the router alert explicitly makes sure that it's
		 * properly padded in option-value cases
		 */
		memset(router_alert.buf, 0, sizeof(router_alert.buf));
		ipv6_router_alert ra;
		ra.opt.len = 2;
		ra.opt.type = 5;
		ra.value = htons(IPV6_ROUTER_ALERT_MLD);
		router_alert.length = cul::align_up2(sizeof(ra) + 2, 8);
		router_alert.buf[1] = 0;

		memcpy(&router_alert.buf[2], &ra, sizeof(ra));

		options.push_back(router_alert);
	}

	flow.options = cul::slice<ip_option>{options.get_buf(), options.size()};
	return ip::v6::send_packet(flow, packet.get());
}

int icmp6_socket::getsockopt(int level, int optname, void *val, socklen_t *len)
{
	if(is_inet_level(level))
		return getsockopt_inet(level, optname, val, len);
	if(level == SOL_SOCKET)
		return getsockopt_socket_level(optname, val, len);
	
	return -ENOPROTOOPT;
}

int icmp6_socket::add_filter(icmp_filter&& f)
{
	scoped_lock g{filters_lock};

	bool is_root = is_root_user();

	if((f.type == ICMP_FILTER_TYPE_UNSPEC || f.type != ICMPV6_ECHO_REQUEST) && !is_root)
	{
		return -EPERM;
	}

	if(filters.size() + 1 > icmp_max_filters && !is_root)
		return -EPERM;
	
	return filters.push_back(cul::move(f)) ? 0 : -ENOMEM;
}

int icmp6_socket::setsockopt(int level, int optname, const void *val, socklen_t len)
{
	if(is_inet_level(level))
		return setsockopt_inet(level, optname, val, len);
	if(level == SOL_SOCKET)
		return setsockopt_socket_level(optname, val, len);

	if(level != SOL_ICMPV6)
		return -ENOPROTOOPT;

	switch(optname)
	{
		case ICMP_ADD_FILTER:
		{
			auto res = get_socket_option<icmp_filter>(val, len);
			if(res.has_error())
				return res.error();
			
			return add_filter(cul::move(res.value()));
		}
	}

	return -ENOPROTOOPT;
}

expected<packetbuf *, int> icmp6_socket::get_datagram(int flags)
{
	scoped_lock g{rx_packet_list_lock};

	int st = 0;
	packetbuf *buf = nullptr;

	do
	{
		if(st == -EINTR)
			return unexpected<int>{st};

		buf = get_rx_head();
		if(!buf && flags & MSG_DONTWAIT)
			return unexpected<int>{-EWOULDBLOCK};

		st = wait_for_dgrams();
	} while(!buf);

	g.keep_locked();

	return buf;
}

ssize_t icmp6_socket::recvmsg(msghdr *msg, int flags)
{
	auto iovlen = iovec_count_length(msg->msg_iov, msg->msg_iovlen);
	if(iovlen < 0)
		return iovlen;

	auto st = get_datagram(flags);
	if(st.has_error())
		return st.error();

	auto buf = st.value();
	ssize_t read = iovlen;

	if(iovlen < buf->length())
		msg->msg_flags = MSG_TRUNC;

	if(flags & MSG_TRUNC)
	{
		read = buf->length();
	}

	auto ptr = buf->data;

	if(msg->msg_name)
	{
		const ip6hdr *hdr = (const ip6hdr *) buf->net_header;
		sockaddr_in6 in;
		explicit_bzero(&in, sizeof(in));

		in.sin6_family = AF_INET6;
		in.sin6_port = 0;
		in.sin6_addr = hdr->src_addr;

		memcpy(msg->msg_name, &in, min(sizeof(in), (size_t) msg->msg_namelen));

		msg->msg_namelen = min(sizeof(in), (size_t) msg->msg_namelen);
	}

	auto packet_length = buf->length();
	auto to_read = min(read, (ssize_t) packet_length);
	
	if(!(flags & MSG_TRUNC))
		read = to_read;

	for(int i = 0; to_read != 0; i++)
	{
		auto iov = msg->msg_iov[i];
		auto to_copy = min((ssize_t) iov.iov_len, to_read);

		if(copy_to_user(iov.iov_base, ptr, to_copy) < 0)
		{
			spin_unlock(&rx_packet_list_lock);
			return -EFAULT;
		}

		ptr += to_copy;
		to_read -= to_copy;
	}

	msg->msg_controllen = 0;

	if(!(flags & MSG_PEEK))
	{
		list_remove(&buf->list_node);
		buf->unref();
	}

	spin_unlock(&rx_packet_list_lock);

	return read;
}

short icmp6_socket::poll(void *poll_file, short events)
{
	scoped_lock g{rx_packet_list_lock};
	short avail_events = POLLOUT;

	if(events & POLLIN)
	{
		if(has_data_available())
			avail_events |= POLLIN;
		else
			poll_wait_helper(poll_file, &rx_wq);
	}

	//printk("avail events: %u\n", avail_events);

	return avail_events & events;
}


icmp6_socket *create_socket(int type)
{
	auto sock = new icmp6_socket();

	if(sock)
	{
		sock->proto_info = &icmp6_proto;
	}

	return sock;
}

}
