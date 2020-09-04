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
#include <endian.h>

#include <onyx/scoped_lock.h>
#include <onyx/dev.h>
#include <onyx/compiler.h>
#include <onyx/utils.h>
#include <onyx/byteswap.h>
#include <onyx/packetbuf.h>
#include <onyx/memory.hpp>
#include <onyx/poll.h>

#include <onyx/net/ip.h>
#include <onyx/net/udp.h>
#include <onyx/net/netif.h>
#include <onyx/net/socket_table.h>
#include <onyx/net/icmp.h>
#include <onyx/net/inet_proto.h>

#include <netinet/in.h>

socket_table udp_socket_table;

const inet_proto udp_proto{"udp", &udp_socket_table};

uint16_t udpv4_calculate_checksum(udp_header_t *header, uint32_t srcip, uint32_t dstip,
                                  bool do_rest_of_packet = true)
{
	uint16_t proto = IPPROTO_UDP << 8;
	uint16_t packet_length = htons(header->len);
	uint16_t __src[2];
	uint16_t __dst[2];

	memcpy(&__src, &srcip, sizeof(srcip));
	memcpy(&__dst, &dstip, sizeof(dstip));

	auto r = __ipsum_unfolded(&__src, sizeof(srcip), 0);
	r = __ipsum_unfolded(&__dst, sizeof(dstip), r);
	r = __ipsum_unfolded(&proto, sizeof(proto), r);
	r = __ipsum_unfolded(&header->len, sizeof(header->len), r);

	if(do_rest_of_packet)
		r = __ipsum_unfolded(header, packet_length, r);

	return ipsum_fold(r);
}

#include <onyx/clock.h>

int udp_socket::send_packet(const msghdr *msg, ssize_t payload_size, in_port_t source_port,
	            in_port_t dest_port, inet_route& route)
{
	auto netif = route.nif;
	auto srcip = route.src_addr.in4.s_addr;
	auto destip = route.dst_addr.in4.s_addr;

	if(payload_size > UINT16_MAX)
		return -EMSGSIZE;

	auto b = make_refc<packetbuf>();
	if(!b)
		return -ENOMEM;

	if(!b->allocate_space(payload_size + get_headers_len() + sizeof(udp_header_t) + PACKET_MAX_HEAD_LENGTH))
		return -ENOMEM;

	b->reserve_headers(get_headers_len() + sizeof(udp_header_t) + PACKET_MAX_HEAD_LENGTH);

	udp_header_t *udp_header = (udp_header_t *) b->push_header(sizeof(udp_header_t));

	memset(udp_header, 0, sizeof(udp_header_t));

	b->transport_header = (unsigned char *) udp_header;

	udp_header->source_port = source_port;
	udp_header->dest_port = dest_port;

	udp_header->len = htons((uint16_t)(sizeof(udp_header_t) + payload_size));
	
	unsigned char *ptr = (unsigned char *) b->put((unsigned int) payload_size);

	for(int i = 0; i < msg->msg_iovlen; i++)
	{
		const auto &vec = msg->msg_iov[i];
		if(copy_from_user(ptr, vec.iov_base, vec.iov_len) < 0)
			return -EINVAL;
		
		ptr += vec.iov_len;
	}

	if(netif->flags & NETIF_SUPPORTS_CSUM_OFFLOAD && !needs_fragmenting(netif, b.get()))
	{
		/* Don't supply the 1's complement of the checksum, since the network stack expects a partial sum */
		udp_header->checksum = ~udpv4_calculate_checksum(udp_header, srcip, destip, false);
		b->csum_offset = &udp_header->checksum;
		b->csum_start = (unsigned char *) udp_header;
		b->needs_csum = 1;
	}
	else
		udp_header->checksum = udpv4_calculate_checksum(udp_header, srcip, destip);

	int ret = ip::v4::send_packet(route, IPPROTO_UDP, b.get(), netif);

	return ret;
}

int udp_socket::bind(sockaddr *addr, socklen_t len)
{
	auto fam = get_proto_fam();
	return fam->bind(addr, len, this);
}

int udp_socket::connect(sockaddr *addr, socklen_t len)
{
	if(!validate_sockaddr_len_pair(addr, len))
		return -EINVAL;

	auto res = sockaddr_to_isa(addr);
	dest_addr = res.first;

	bool on_ipv4_mode = res.second == AF_INET && domain == AF_INET6;

	//printk("udp: Connected to address %x\n", dest_addr.in4.s_addr);

	if(!bound)
	{
		/* TODO: Dunno if this can work */
		auto fam = get_proto_fam();
		int st = fam->bind_any(this);
		if(st < 0)
			return st;
	}

	ipv4_on_inet6 = on_ipv4_mode;

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

ssize_t udp_socket::sendmsg(const msghdr *msg, int flags)
{
	sockaddr *addr = (sockaddr *) msg->msg_name;
	if(addr && !validate_sockaddr_len_pair(addr, msg->msg_namelen))
		return -EINVAL;

	inet_sock_address dest = dest_addr;
	int our_domain = effective_domain();

	auto payload_size = iovec_count_length(msg->msg_iov, msg->msg_iovlen);
	if(payload_size < 0)
		return payload_size;

	if(addr)
	{
		auto res = sockaddr_to_isa(addr);
		dest = res.first;
		our_domain = res.second;
	}

	if(!connected && addr == nullptr)
		return -ENOTCONN;

	inet_route route;

	if(connected && route_cache_valid)
	{
		route = route_cache;
	}
	else
	{
		auto fam = get_proto_fam();
		auto result = fam->route(src_addr, dest, our_domain);
		if(result.has_error())
		{
			printk("died with error %d\n", result.error());
			return result.error();
		}

		route = result.value();
	}

	/* TODO: Connect ipv6 support up */
	if(int st = send_packet(msg, payload_size, src_addr.port, dest.port,
			   route); st < 0)
	{
		return st;
	}

	return payload_size;
}

socket *udp_create_socket(int type)
{
	auto sock = new udp_socket;

	if(sock)
	{
		sock->proto_info = &udp_proto;
	}

	return sock;
}

int udp_init_netif(netif *netif)
{
	return 0;
}

bool valid_udp_packet(udp_header_t *header, size_t length)
{
	if(sizeof(udp_header_t) > length)
		return false;
	if(ntohs(header->len) > length)
		return false;

	return true;
}

int udp_handle_packet(netif *netif, packetbuf *buf)
{
	udp_header_t *udp_header = (udp_header_t *) buf->data;

	if(!valid_udp_packet(udp_header, buf->length()))
		return -EINVAL;
	
	auto header = (ip_header *) buf->net_header;

	sockaddr_in socket_dst;
	ipv4_to_sockaddr(header->source_ip, udp_header->source_port, socket_dst);

	auto socket = inet_resolve_socket<udp_socket>(header->source_ip,
                      udp_header->source_port, udp_header->dest_port, IPPROTO_UDP,
					  netif, true, &udp_proto);
	if(!socket)
	{
		icmp::dst_unreachable_info dst_un{ICMP_CODE_PORT_UNREACHABLE, 0,
		                (const unsigned char *) udp_header, header};
		icmp::send_dst_unreachable(dst_un, netif);
		return 0;
	}

	buf->transport_header = (unsigned char *) udp_header;
	buf->data += sizeof(udp_header_t);

	socket->rx_dgram(buf);

	socket->unref();
	return 0;
}

expected<packetbuf *, int> udp_socket::get_datagram(int flags)
{
	scoped_lock g{&rx_packet_list_lock};

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

static void copy_msgname_to_user(struct msghdr *msg, packetbuf *buf, bool isv6)
{
	udp_header_t *udp_header = (udp_header_t *) buf->transport_header;

	if(buf->domain == AF_INET && !isv6)
	{
		const ip_header *hdr = (const ip_header *) buf->net_header;
		sockaddr_in in;
		explicit_bzero(&in, sizeof(in));

		in.sin_family = AF_INET;
		in.sin_port = udp_header->source_port;
		in.sin_addr.s_addr = hdr->source_ip;

		memcpy(msg->msg_name, &in, min(sizeof(in), (size_t) msg->msg_namelen));

		msg->msg_namelen = min(sizeof(in), (size_t) msg->msg_namelen);
	}
	else if(buf->domain == AF_INET && isv6)
	{
		const ip_header *hdr = (const ip_header *) buf->net_header;
		/* Create a v4-mapped v6 address */
		sockaddr_in6 in6;
		explicit_bzero(&in6, sizeof(in6));

		in6.sin6_family = AF_INET6;
		in6.sin6_flowinfo = 0;
		in6.sin6_port = udp_header->source_port;
		in6.sin6_scope_id = 0;
		in6.sin6_addr = ip::v6::ipv4_to_ipv4_mapped(hdr->source_ip);

		memcpy(msg->msg_name, &in6, min(sizeof(in6), (size_t) msg->msg_namelen));

		msg->msg_namelen = min(sizeof(in6), (size_t) msg->msg_namelen);
	}
	else // if(buf->domain == AF_INET6)
	{
		const ip6hdr *hdr = (const ip6hdr *) buf->net_header;

		sockaddr_in6 in6;
		explicit_bzero(&in6, sizeof(in6));

		in6.sin6_family = AF_INET6;
		/* TODO: Probably not correct */
		in6.sin6_flowinfo = hdr->flow_label[0] | hdr->flow_label[1] << 8 | hdr->flow_label[2] << 16;;
		in6.sin6_port = udp_header->source_port;
		memcpy(&in6.sin6_addr, &hdr->src_addr, sizeof(hdr->src_addr));

		memcpy(msg->msg_name, &in6, msg->msg_namelen);

		msg->msg_namelen = min(sizeof(in6), (size_t) msg->msg_namelen);
	}
}

ssize_t udp_socket::recvmsg(msghdr *msg, int flags)
{
	auto iovlen = iovec_count_length(msg->msg_iov, msg->msg_iovlen);
	if(iovlen < 0)
		return iovlen;

	auto st = get_datagram(flags);
	if(st.has_error())
		return st.error();

	auto buf = st.value();
	ssize_t read = min(iovlen, (long) buf->length());
	ssize_t was_read = 0;
	ssize_t to_ret = read;

	if(iovlen < buf->length())
		msg->msg_flags = MSG_TRUNC;

	if(flags & MSG_TRUNC)
	{
		to_ret = buf->length();
	}

	const unsigned char *ptr = buf->data;

	if(msg->msg_name)
	{
		copy_msgname_to_user(msg, buf, domain == AF_INET6);
	}

	for(int i = 0; i < msg->msg_iovlen; i++)
	{
		auto iov = msg->msg_iov[i];
		auto to_copy = min((ssize_t) iov.iov_len, read - was_read);
		if(copy_to_user(iov.iov_base, ptr, to_copy) < 0)
		{
			spin_unlock(&rx_packet_list_lock);
			return -EFAULT;
		}

		was_read += to_copy;

		ptr += to_copy;
	}

	msg->msg_controllen = 0;

	if(!(flags & MSG_PEEK))
	{
		list_remove(&buf->list_node);
		buf->unref();
	}

	spin_unlock(&rx_packet_list_lock);

#if 0
	printk("recv success %ld bytes\n", read);
	printk("iovlen %ld\n", iovlen);
#endif

	return to_ret;
}

int udp_socket::getsockopt(int level, int optname, void *val, socklen_t *len)
{
	if(is_inet_level(level))
		return getsockopt_inet(level, optname, val, len);
	if(level == SOL_SOCKET)
		return getsockopt_socket_level(optname, val, len);
	
	return -ENOPROTOOPT;
}

int udp_socket::setsockopt(int level, int optname, const void *val, socklen_t len)
{
	if(is_inet_level(level))
		return setsockopt_inet(level, optname, val, len);
	if(level == SOL_SOCKET)
		return setsockopt_socket_level(optname, val, len);
	
	return -ENOPROTOOPT;
}

short udp_socket::poll(void *poll_file, short events)
{
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
