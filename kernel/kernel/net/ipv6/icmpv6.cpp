/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <errno.h>

#include <onyx/net/inet_csum.h>
#include <onyx/net/ipv6.h>
#include <onyx/packetbuf.h>
#include <onyx/net/icmpv6.h>

namespace icmpv6
{

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

	if(!buf->allocate_space(PACKET_MAX_HEAD_LENGTH + sizeof(ip6hdr) +
	                        sizeof(icmpv6_header) + packet_data.size_bytes()))
		return -ENOMEM;

	buf->reserve_headers(PACKET_MAX_HEAD_LENGTH + sizeof(ip6hdr) +
	                        sizeof(icmpv6_header));
	
	auto hdr = (icmpv6_header *) buf->push_header(sizeof(icmpv6_header));
	hdr->type = data.type;
	hdr->code = data.code;
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

	return ip::v6::send_packet(data.route, IPPROTO_ICMPV6, buf.get(), data.route.nif);
}

}
