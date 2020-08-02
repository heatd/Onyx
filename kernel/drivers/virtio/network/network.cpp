/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include "../virtio.hpp"
#include "network.hpp"

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

int network_vdev::__sendpacket(packetbuf *buf, netif *nif)
{
	auto dev = static_cast<network_vdev *>(nif->priv);

	return dev->send_packet(buf);
}

static constexpr unsigned int network_receiveq = 0;
static constexpr unsigned int network_transmitq = 1;

int network_vdev::send_packet(packetbuf *buf)
{
	int st = 0;

	auto hdr = reinterpret_cast<virtio_net_hdr *>(buf->push_header(sizeof(virtio_net_hdr)));
	memset(hdr, 0, sizeof(*hdr));
	hdr->gso_type = VIRTIO_NET_HDR_GSO_NONE;
	auto &transmit = virtqueue_list[network_transmitq];

	/* TODO: Add proper sg-list support to virtio_buf_list */
	virtio_buf_list list{transmit};
	auto addr = buf->page_vec[0].to_iter(buf->start_page_off()).to_pointer<uint8_t *>();
	if(!list.prepare(addr, buf->length(), false))
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

virtio::network_features supported_features[] =
{
	network_features::csum,
	/*network_features::guest_csum,
	network_features::guest_tso4,
	network_features::guest_tso6,*/
	network_features::host_tso4,
	network_features::host_tso6,
	//network_features::guest_ufo,
	network_features::host_ufo
};

bool network_vdev::perform_subsystem_initialization()
{
	unsigned int nif_flags = 0;

	if(raw_has_feature(network_features::mac))
	{
		signal_feature(network_features::mac);
	}
	else
	{
		/* The device should support the mac address feature */
		return false;
	}

	for(auto feature : supported_features)
	{
		if(raw_has_feature(feature))
		{
			signal_feature(feature);
			if(feature == network_features::csum)
				nif_flags |= NETIF_SUPPORTS_CSUM_OFFLOAD;
			
			if(feature == network_features::host_tso4)
				nif_flags |= NETIF_SUPPORTS_TSO4;
			
			if(feature == network_features::host_tso6)
				nif_flags |= NETIF_SUPPORTS_TSO6;
			
			if(feature == network_features::host_ufo)
				nif_flags |= NETIF_SUPPORTS_UFO;
		}
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
	if(!nif)
	{
		set_failure();
		return false;
	}

	nif->name = "eth0";
	nif->flags |= NETIF_LINKUP | nif_flags;
	nif->priv = this;
	nif->sendpacket = virtio::network_vdev::__sendpacket;
	nif->mtu = 1500;

	cul::slice<uint8_t, 6> m{nif->mac_address, 6};
	get_mac(m);

	netif_register_if(nif.get_data());

	return true;
}

network_vdev::~network_vdev()
{
	if(rx_pages)  free_pages(rx_pages);
}

unique_ptr<vdev> create_network_device(pci_device *dev)
{
	return make_unique<network_vdev>(dev);
}

}
