/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _VIRTIO_NET_HPP
#define _VIRTIO_NET_HPP

#include <stdint.h>
#include <onyx/slice.hpp>
#include <onyx/memory.hpp>
#include <onyx/net/network.h>

#include "../virtio.hpp"

namespace virtio
{

struct virtio_net_hdr
{ 
#define VIRTIO_NET_HDR_F_NEEDS_CSUM    1 
#define VIRTIO_NET_HDR_F_DATA_VALID    2 
#define VIRTIO_NET_HDR_F_RSC_INFO      4 
	uint8_t flags; 
#define VIRTIO_NET_HDR_GSO_NONE        0 
#define VIRTIO_NET_HDR_GSO_TCPV4       1 
#define VIRTIO_NET_HDR_GSO_UDP         3 
#define VIRTIO_NET_HDR_GSO_TCPV6       4 
#define VIRTIO_NET_HDR_GSO_ECN      0x80 
	uint8_t gso_type; 
	uint16_t hdr_len;
	uint16_t gso_size; 
	uint16_t csum_start; 
	uint16_t csum_offset; 
	uint16_t num_buffers; 
} __attribute__((packed));

class network_vdev : public vdev
{
private:
	void get_mac(cul::slice<uint8_t, 6>& mac_buf);
	unique_ptr<netif> nif;
	struct page *rx_pages;

	static int __sendpacket(packetbuf *buf, netif *nif);
	static void __rx_end(netif *nif);
	static int __poll_rx(netif *nif);
	
	int send_packet(packetbuf *buf);

	void rx_end();
	int poll_rx();

	void process_packet(unsigned long paddr, unsigned long len);
public:
	network_vdev(pci::pci_device *d) : vdev(d) {}
	~network_vdev();
	
	bool perform_subsystem_initialization() override;
	bool setup_rx();

	void handle_used_buffer(const virtq_used_elem &elem, virtq *vq) override;
	handle_vq_irq_result driver_handle_vq_irq(unsigned int nr) override;
};

enum network_registers
{
	mac_base = 0,
	status = 6,
	max_virtqueue_pairs = 8,
	mtu = 10,
	speed = 12,
	duplex = 16
};

enum network_features
{
	csum = 0,
	guest_csum = 1,
	ctrl_guest_offloads = 2,
	feature_mtu = 3,
	mac = 5,
	guest_tso4 = 7,
	guest_tso6 = 8,
	guest_ecn = 9,
	guest_ufo = 10,
	host_tso4 = 11,
	host_tso6 = 12,
	host_ecn = 13,
	host_ufo = 14,
	merge_rxbuf = 15,
	feature_status = 16,
	ctrl_vq = 17,
	ctrl_rx = 18,
	ctrl_vlan = 19,
	guest_announce = 21,
	feature_mq = 22,
	ctrl_mac_addr = 23,
	rsc_ext = 61,
	standby = 62
};

};

#endif

