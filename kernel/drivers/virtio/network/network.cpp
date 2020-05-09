/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include "../virtio.hpp"

#include <onyx/net/network.h>
#include <onyx/net/ethernet.h>
#include <onyx/slice.hpp>

namespace virtio
{


void network_vdev::get_mac(cul::slice<uint8_t, 6>& mac_buf)
{
	unsigned int i = 0;
	for(auto& b : mac_buf)
		b = read<uint8_t>(network_registers::mac_base + i++);
}

bool network_vdev::perform_subsystem_initialization()
{
	if(has_feature(network_features::mac))
	{
		signal_feature(network_features::mac);
	}
	else
	{
		/* The device should support the mac address feature */
		return false;
	}

	if(!finish_feature_negotiation())
		return false;

	/* TODO: Support VIRTIO_NET_F_MQ */
	if(!create_virtqueue(0, get_max_virtq_size(0)) ||
	   !create_virtqueue(1, get_max_virtq_size(1)) ||
	   !create_virtqueue(2, get_max_virtq_size(2)))
	{
		printk("virtio: Failed to create virtqueues\n");
		return false;
	}
	
	struct page *p = alloc_page(PAGE_ALLOC_NO_ZERO);
	assert(p != nullptr);
	virtio_net_hdr *hdr = (virtio_net_hdr *) PAGE_TO_VIRT(p);
	hdr->flags = 0;
	hdr->gso_type = VIRTIO_NET_HDR_GSO_NONE;
	ethernet_header_t *he = (ethernet_header_t *)(hdr + 1);
	he->ethertype = PROTO_IPV6;
	
	for(auto& b : he->mac_dest)
		b = 0xff;

	virtio_buf_list l{virtqueue_list[1].get_data()};
	
	assert(l.prepare(hdr, 200, false) != false);

	virtqueue_list[1]->put_buffer(l);
	printk("Sent!\n");

	/* TODO: Fix this */
	return true;
}

}
