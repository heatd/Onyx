/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include "../virtio.hpp"

#include <onyx/slice.hpp>
#include <onyx/page.h>

#include <onyx/net/network.h>
#include <onyx/net/ethernet.h>

struct page_frag_alloc_info
{
	struct page *page_list;
	struct page *curr;
	size_t off;
};

struct page_frag_res
{
	struct page *page;
	size_t off;
};

extern "C" struct page_frag_res page_frag_alloc(struct page_frag_alloc_info *inf, size_t size);

namespace virtio
{


void network_vdev::get_mac(cul::slice<uint8_t, 6>& mac_buf)
{
	unsigned int i = 0;
	for(auto& b : mac_buf)
		b = read<uint8_t>(network_registers::mac_base + i++);
}

size_t net_if_getlen(void *info, struct packetbuf_proto **next, void **next_info)
{
	auto vdev = static_cast<network_vdev *>(info);
	(void) vdev;

	*next = nullptr;
	*next_info = info;

	return sizeof(virtio_net_hdr);
}


packetbuf_proto net_if_proto =
{
	.name = "virtio_net",
	.get_len = net_if_getlen
};

packetbuf_proto *network_vdev::get_packetbuf_proto(netif *n)
{
	return eth_get_packetbuf_proto();
}

int network_vdev::__sendpacket(const void *buffer, uint16_t size, netif *nif)
{
	auto dev = static_cast<network_vdev *>(nif->priv);

	return dev->send_packet(buffer, size);
}

static constexpr unsigned int network_receiveq = 0;
static constexpr unsigned int network_transmitq = 1;

int network_vdev::send_packet(const void *buffer, uint16_t size)
{
	/* TODO: We're casting away const here! Ewwwwwwwwwwww - passing [buffer, size] here
	 * isn't a good idea - I don't like it and it forces us to do this disgusting thing.
	 */
	int st = 0;

	/* This page allocation + copy is ugly, I really really don't like it but the
	 * network stack packet submission is this broken...
	 * TODO: Fix.
	 */
	
	/* The networking subsystem should benefit from something like, for example, a packetbuf struct that holds
	 * a bunch more of packet data and gets passed *everywhere*, including send_packet, instead of being a
	 * glorified buffer allocation system as-is right now. Also, allocating raw pages instead of needing either a copy
	 * or dma_get_ranges
	 */

	struct page *p = alloc_page(PAGE_ALLOC_NO_ZERO);
	if(!p)
		return -ENOMEM;

	auto hdr = reinterpret_cast<virtio_net_hdr *>(const_cast<void *>(buffer));
	memset(hdr, 0, sizeof(*hdr));
	hdr->gso_type = VIRTIO_NET_HDR_GSO_NONE;
	auto &transmit = virtqueue_list[network_transmitq];

	memcpy(PAGE_TO_VIRT(p), buffer, size);

	virtio_buf_list list{transmit};
	if(!list.prepare(PAGE_TO_VIRT(p), size, false))
	{
		st = -EIO;
		goto out_error;
	}
	
	if(!transmit->allocate_descriptors(list))
	{
		st = -EIO;
		goto out_error;
	}

	if(!transmit->put_buffer(list))
	{
		st = -EIO;
		goto out_error;
	}

	return 0;
out_error:
	free_page(p);
	return st;
}

static constexpr unsigned int rx_buf_size = 1526;

bool network_vdev::setup_rx()
{
	auto &vq = virtqueue_list[network_receiveq];
	auto qsize = vq->get_queue_size();

	rx_pages = alloc_pages(vm_size_to_pages(rx_buf_size * qsize),
                                             PAGE_ALLOC_NO_ZERO);
	if(!rx_pages)
	{
		return false;
	}

	struct page_frag_alloc_info alloc_info;
	alloc_info.curr = alloc_info.page_list = rx_pages;
	alloc_info.off = 0;

	for(unsigned int i = 0; i < qsize; i++)
	{
		auto [page, off] = page_frag_alloc(&alloc_info, rx_buf_size);

		virtio_buf_list l{vq};

		if(!l.prepare((char *) PAGE_TO_VIRT(page) + off, rx_buf_size, true))
			return false;

		if(!vq->allocate_descriptors(l))
			return false;

		bool is_last = i == qsize - 1;

		/* Only notify the buffer if it's the last one, as to avoid redudant notifications */
		if(!vq->put_buffer(l, is_last))
			return false;
	}

	return true;
}

void network_vdev::handle_used_buffer(const virtq_used_elem &elem, const virtq *vq)
{
	auto nr = vq->get_nr();

	if(nr == network_receiveq)
	{
		auto [paddr, len] = vq->get_buf_from_id(elem.id);
		auto packet_base = paddr + PHYS_BASE + sizeof(virtio_net_hdr);
		network_dispatch_receive((uint8_t *) packet_base, elem.length - sizeof(virtio_net_hdr),
		                          nif.get_data());
	}
	else if(nr == network_transmitq)
	{
		auto [paddr, len] = vq->get_buf_from_id(elem.id);
		page *p = phys_to_page(paddr);
		free_page(p);
	}
}

bool network_vdev::perform_subsystem_initialization()
{
	if(raw_has_feature(network_features::mac))
	{
		signal_feature(network_features::mac);
	}
	else
	{
		/* The device should support the mac address feature */
		return false;
	}

	if(!do_device_independent_negotiation() || !finish_feature_negotiation())
	{
		set_failure();
		return false;
	}

	/* TODO: Support VIRTIO_NET_F_MQ */
	if(!create_virtqueue(0, get_max_virtq_size(0)) ||
	   !create_virtqueue(1, get_max_virtq_size(1)) ||
	   !create_virtqueue(2, get_max_virtq_size(2)))
	{
		printk("virtio: Failed to create virtqueues\n");
		set_failure();
		return false;
	}

	finalise_driver_init();

	if(!setup_rx())
	{
		set_failure();
		return false;
	}

	nif = make_unique<netif>();

	nif->name = "eth0";
	nif->flags |= NETIF_LINKUP;
	nif->priv = this;
	nif->sendpacket = virtio::network_vdev::__sendpacket;
	nif->mtu = 1514;
	nif->if_proto = &virtio::net_if_proto;
	nif->get_packetbuf_proto = virtio::network_vdev::get_packetbuf_proto;

	cul::slice<uint8_t, 6> m{nif->mac_address, 6};
	get_mac(m);

	netif_register_if(nif.get_data());

	return true;
}

network_vdev::~network_vdev()
{
	if(rx_pages)  free_pages(rx_pages);
}

}
