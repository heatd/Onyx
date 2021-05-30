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

void network_vdev::__rx_end(netif *nif)
{
	auto dev = static_cast<network_vdev *>(nif->priv);

	dev->rx_end();
}

int network_vdev::__poll_rx(netif *nif)
{
	auto dev = static_cast<network_vdev *>(nif->priv);

	return dev->poll_rx();
}


static constexpr unsigned int network_receiveq = 0;
static constexpr unsigned int network_transmitq = 1;

void network_vdev::rx_end()
{
	auto &vq = get_vq(network_receiveq);

	vq->enable_interrupts(); 
}

int network_vdev::poll_rx()
{
	auto &vq = get_vq(network_receiveq);

	vq->handle_irq();
	return 0;
}

int network_vdev::send_packet(packetbuf *buf)
{
	int st = 0;

	auto hdr = reinterpret_cast<virtio_net_hdr *>(buf->push_header(sizeof(virtio_net_hdr)));
	memset(hdr, 0, sizeof(*hdr));
	hdr->gso_type = VIRTIO_NET_HDR_GSO_NONE;
	auto &transmit = virtqueue_list[network_transmitq];

	virtio_buf_list list{transmit};

	unsigned int vec_index = 0;

	for(const auto &v_ : buf->page_vec)
	{
		// We make a copy because we might need to offset the start of the page when we're on the
		// first entry, due to header offsetting 
		page_iov v = v_;
		if(!vec_index)
		{
			auto start = buf->buffer_start_off();
			v.page_off += start;
			v.length -= start;
		}

		if(!v.page)
			break;

		// TODO: This seems like a not-very-solid design
		v.page->priv = (unsigned long) &list;

		if(!list.prepare(v, false))
		{
			return -ENOMEM;
		}

		vec_index++;
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

	// arghhh, busy sleeping... we can't do a wait in networking code
	// FIXME: Redesign?
	while(!list.all_bufs_used());

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

void network_vdev::process_packet(unsigned long paddr, unsigned long len)
{
	auto packet_base = PHYS_TO_VIRT(paddr);
	auto pckt = make_refc<packetbuf>(); 
	if(!pckt)
		return;

	auto real_len = len - sizeof(virtio_net_hdr);
	auto header = (virtio_net_hdr*) packet_base;

	if(!pckt->allocate_space(real_len))
		return;

	if(header->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)
	{
		pckt->needs_csum = 1;
	}

	void *p = pckt->put(real_len);

	memcpy(p, header + 1, real_len);

	netif_process_pbuf(nif.get(), pckt.get());
}

void network_vdev::handle_used_buffer(const virtq_used_elem &elem, virtq *vq)
{
	auto nr = vq->get_nr();

	if(nr == network_receiveq)
	{
		auto [paddr, len] = vq->get_buf_from_id(elem.id);
		process_packet(paddr, len);
	}
	else if(nr == network_transmitq)
	{
		auto [paddr, len] = vq->get_buf_from_id(elem.id);
		page *p = phys_to_page(paddr);

		// arrrg, I don't like this 'using priv' thing: refer to the other TODO
		((virtio_buf_list *) p->priv)->increment_used();
	}
}

handle_vq_irq_result network_vdev::driver_handle_vq_irq(unsigned int nr)
{
	if(nr == network_receiveq)
	{
		const auto &vq = get_vq(nr);

		netif_signal_rx(nif.get());

		vq->disable_interrupts();

		return handle_vq_irq_result::DELAY;
	}

	return handle_vq_irq_result::HANDLE;
}

static virtio::network_features supported_features[] =
{
	network_features::csum,
	/*network_features::guest_csum,
	network_features::guest_tso4,
	network_features::guest_tso6,*/
	//network_features::host_tso4,
	//network_features::host_tso6,
	//network_features::guest_ufo,
	//network_features::host_ufo
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
	nif->poll_rx = virtio::network_vdev::__poll_rx;
	nif->rx_end = virtio::network_vdev::__rx_end;
	nif->dll_ops = &eth_ops;

	cul::slice<uint8_t, 6> m{nif->mac_address, 6};
	get_mac(m);

	netif_register_if(nif.get_data());

	return true;
}

network_vdev::~network_vdev()
{
	if(rx_pages)  free_pages(rx_pages);
}

unique_ptr<vdev> create_network_device(pci::pci_device *dev)
{
	return make_unique<network_vdev>(dev);
}

}
