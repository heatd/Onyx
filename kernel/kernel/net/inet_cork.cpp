/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <onyx/utility.hpp>

#include <onyx/net/inet_cork.h>
#include <onyx/net/ip.h>
#include <onyx/net/ipv6.h>


int inet_cork::append_data(const iovec *vec, size_t vec_len, size_t proto_hdr_size, size_t max_packet_len)
{
	size_t read_in_vec = 0;

	list_for_every(&packet_list)
	{
		if(!vec_len)
			break;

		auto packet = list_head_cpp<packetbuf>::self_from_list_head(l);

		if(packet->length() < max_packet_len)
		{
			/* OOOH, we've got some room, let's expand! */
			const uint8_t *ubuf = (uint8_t *) vec->iov_base + read_in_vec;
			auto len = vec->iov_len - read_in_vec;
			auto to_expand = cul::clamp(len, UINT_MAX);

			auto st = packet->expand_buffer(ubuf, to_expand);

			if(st < 0)
			{
				return -ENOMEM;
			}

			read_in_vec += st;

			if(read_in_vec == vec->iov_len)
			{
				vec++;
				read_in_vec = 0;
				vec_len--;
			}
		}
	}

	return alloc_and_append(vec, vec_len, proto_hdr_size, max_packet_len);
}

int inet_cork::alloc_and_append(const iovec *vec, size_t vec_len, size_t proto_hdr_len, size_t max_packet_len)
{
	max_packet_len -= proto_hdr_len + PACKET_MAX_HEAD_LENGTH;
	size_t added_from_vec = 0;
	while(vec_len)
	{
		auto packet = new packetbuf;
		if(!packet)
			return -ENOMEM;
		
		auto to_alloc = cul::clamp(vec->iov_len - added_from_vec, max_packet_len);

		auto ubuf = (const uint8_t *) vec->iov_base + added_from_vec;

		if(!packet->allocate_space(to_alloc))
		{
			delete packet;
			return -ENOMEM;
		}

		packet->reserve_headers(proto_hdr_len + PACKET_MAX_HEAD_LENGTH);

		auto st = packet->expand_buffer(ubuf, to_alloc);
		printk("expand buffer %ld", st);

		assert((size_t) st == to_alloc);

		added_from_vec += to_alloc;

		list_add_tail(&packet->list_node, &packet_list);

		if(added_from_vec == vec->iov_len)
		{
			added_from_vec = 0;
			vec_len--;
			vec++;
		}
	}

	return 0;
}

int inet_cork::send(const iflow &flow, void (*prepare_headers)(packetbuf *buf, const iflow &flow))
{
	/* TODO: Put pending in inet_cork so inet_cork knows what it's dealing with */
	int pending = AF_INET;

	list_for_every_safe(&packet_list)
	{
		auto pbf = list_head_cpp<packetbuf>::self_from_list_head(l);
		
		prepare_headers(pbf, flow);

		list_remove(&pbf->list_node);

		int st = 0;

		if(pending == AF_INET)
		{
			st = ip::v4::send_packet(flow, pbf);
		}

		delete pbf;

		if(st < 0)
			return st;
	}

	return 0;
}
