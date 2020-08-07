/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Don't change the include order! Maybe TOFIX? */
#include <onyx/net/ethernet.h>
#include <onyx/net/netif.h>
#include <onyx/spinlock.h>
#include <onyx/net/arp.h>
#include <onyx/compiler.h>
#include <onyx/net/ip.h>
#include <onyx/log.h>
#include <onyx/byteswap.h>
#include <onyx/memory.hpp>
#include <onyx/net/neighbour.h>

/* TODO: Maybe the neighbour_table could replace some code below, if we add a few virtual functions */
static neighbour_table arp_table{AF_INET};
static constexpr hrtime_t arp_response_timeout = 250 * NS_PER_MS;

/* 20 minutes in milis */
static constexpr unsigned long arp_validity_time_ms = 1200000;

int arp_handle_packet(arp_request_t *arp, uint16_t len, struct netif *netif)
{
	/* We're not interested in handling requests right now. TODO: Maybe add this? */
	if(htons(arp->operation) != ARP_OP_REPLY)
		return 0;

	in_addr_t req_ip = arp->sender_proto_address;
	neigh_proto_addr addr;
	addr.in4addr.s_addr = req_ip;

	auto [ptr, __created] = arp_table.add(addr, true);
	if(!ptr)
		return 0;

	unsigned char *mac = new unsigned char[ETH_ALEN];
	if(!mac)
		return 0;

	cul::slice<unsigned char> sl{mac, ETH_ALEN};
	ptr->set_hwaddr(sl);
	ptr->flags |= NEIGHBOUR_FLAG_HAS_RESPONSE;

	return 0;
}

int arp_submit_request(uint32_t target_addr, struct netif *netif)
{
	auto buf = make_unique<packetbuf>();
	if(!buf)
		return -ENOMEM;
	
	if(!buf->allocate_space(sizeof(arp_request_t) + PACKET_MAX_HEAD_LENGTH))
		return -ENOMEM;
	
	buf->reserve_headers(sizeof(arp_request_t) + PACKET_MAX_HEAD_LENGTH);

	auto arp = reinterpret_cast<arp_request_t *>(buf->push_header(sizeof(arp_request_t)));
	memset(arp, 0, sizeof(arp_request_t));
	arp->htype = htons(ARP_ETHERNET);
	arp->ptype = 0x0008;
	arp->hlen = ARP_HLEN_ETHERNET;
	arp->plen = ARP_PLEN_IPV4;
	arp->operation = htons(ARP_OP_REQUEST);
	
	memcpy(&arp->sender_hw_address, &netif->mac_address, 6);
	arp->target_hw_address[0] = 0xFF;
	arp->target_hw_address[1] = 0xFF;
	arp->target_hw_address[2] = 0xFF;
	arp->target_hw_address[3] = 0xFF;
	arp->target_hw_address[4] = 0xFF;
	arp->target_hw_address[5] = 0xFF;
	arp->sender_proto_address = netif->local_ip.sin_addr.s_addr;
	arp->target_proto_address = target_addr;
	if(int st = netif->dll_ops->setup_header(buf.get(),
	            tx_type::broadcast, tx_protocol::arp, netif, nullptr); st < 0)
		return st;

	return netif_send_packet(netif, buf.get());
}

expected<shared_ptr<neighbour>, int> arp_resolve_in(uint32_t ip, struct netif *netif)
{
	neigh_proto_addr addr;
	addr.in4addr.s_addr = ip;

	auto [ptr, created] = arp_table.add(addr);
	if(!ptr)
		return unexpected{-ENOMEM};

	if(ptr->flags & NEIGHBOUR_FLAG_UNINITIALISED)
	{
		if(created)
		{
			bool failed = false;
			if(ip == INADDR_BROADCAST)
			{
				auto _ptr = new unsigned char[ETH_ALEN];
				
				if(_ptr)
				{
					memset(_ptr, 0xff, ETH_ALEN);
					auto sl = cul::slice<unsigned char>{_ptr, ETH_ALEN};
					ptr->set_hwaddr(sl);
					ptr->flags |= NEIGHBOUR_FLAG_HAS_RESPONSE | NEIGHBOUR_FLAG_BROADCAST;
				}
				else
				{
					failed = true;
				}
			}

			if(failed || (ip != INADDR_BROADCAST && arp_submit_request(ip, netif) < 0))
			{
				arp_table.remove(ptr.get_data());
				return unexpected{-ENOMEM};
			}
		}

		auto t0 = clocksource_get_time();

		/* TODO: Add a wait_for_bit that can let us wait for random things
		 * without taking up permanent space in the structure
		 */
		while(!(ptr->flags & NEIGHBOUR_FLAG_HAS_RESPONSE) && clocksource_get_time() - t0 <= arp_response_timeout)
			sched_sleep_ms(15);
		
		if(!(ptr->flags & NEIGHBOUR_FLAG_HAS_RESPONSE))
		{
			if(created)
				arp_table.remove(ptr.get_data());
			return unexpected{-ENETUNREACH};
		}
	
		if(created)
		{
			ptr->set_validity(arp_validity_time_ms);
			ptr->set_initialised();
		}
	}

	return ptr;
}
