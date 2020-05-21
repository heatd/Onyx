/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _VIRTIO_PCI_HPP
#define _VIRTIO_PCI_HPP

#include <stdint.h>


#define VIRTIO_VENDOR_ID	0x1af4
#define VIRTIO_VENDOR_ID2	0x1b36

namespace virtio
{

enum vendor_pci_cap
{
	common = 1,
	notify,
	isr,
	device,
	pci
};

constexpr uint16_t network_pci_subsys = 0x1; 
constexpr uint16_t block_pci_subsys = 0x2;
constexpr uint16_t gpu_pci_subsys = 16;
constexpr uint16_t pci_device_id_base = 0x1040;
constexpr uint16_t pci_device_id_base_transitional = 0x1000;
constexpr uint16_t pci_device_id_max = 0x107f;

/* These represent offsets after the generic cap header */
constexpr size_t pci_off = 2;
constexpr size_t cfg_type_off = pci_off + 1;
constexpr size_t bar_off = pci_off + 2;
constexpr size_t offset_off = pci_off + 6;
constexpr size_t length_off = pci_off + 10;


enum pci_common_cfg
{
	device_feature_select = 0,
	device_feature = 4,
	driver_feature_select = 8,
	driver_feature = 12,
	msix_config = 16,
	num_queues = 18,
	device_status = 20,
	config_generation = 21,
	queue_select = 22,
	queue_size = 24,
	queue_msix_vector = 26,
	queue_enable = 28,
	queue_notify_off = 30,
	queue_desc_low = 32,
	queue_desc_high = 36,
	queue_driver_low = 40,
	queue_driver_high = 44,
	queue_device_low = 48,
	queue_device_high = 52,
	pci_common_cfg_max = 56
};

enum isr_cfg
{
	isr_status = 0
};

#define VIRTIO_ISR_CFG_QUEUE_INTERRUPT     (1 << 0)
#define VIRTIO_ISR_CFG_DEVICE_CFG_INT      (1 << 1)

constexpr size_t notify_off_multiplier = length_off + 4;

};

#endif
