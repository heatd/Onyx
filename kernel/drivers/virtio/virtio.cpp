/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <assert.h>

#include <onyx/driver.h>
#include <onyx/dev.h>
#include <onyx/acpi.h>
#include <onyx/smart.h>

#include <pci/pci.h>

/* For QXL_DEVICE_ID_STABLE */
#include "../qxl/qxl_dev.h"

#define MPRINTF(...)	printf("virtio: " __VA_ARGS__)

#define VIRTIO_VENDOR_ID	0x1af4
#define VIRTIO_VENDOR_ID2	0x1b36


namespace virtio
{

constexpr uint16_t network_pci_subsys = 0x1; 
constexpr uint16_t block_pci_subsys = 0x2;

enum class vendor_pci_cap
{
	common = 1,
	notify,
	isr,
	device,
	pci
};

/* These represent offsets after the generic cap header */
constexpr size_t pci_off = 2;
constexpr size_t cfg_type_off = pci_off + 1;
constexpr size_t bar_off = pci_off + 2;
constexpr size_t offset_off = pci_off + 6;
constexpr size_t length_off = pci_off + 10;

class device
{
protected:
	struct pci_device *dev;
public:
	device(struct pci_device *dev) : dev(dev) {}
	virtual ~device() {}
	device(const device& rhs) = delete;
	device(device&& rhs) = delete;
	
	device& operator=(const device& rhs) = delete;
	device& operator=(device&& rhs) = delete;

	void perform_base_virtio_initialization() {}
	virtual bool perform_subsystem_initialization() = 0;
};

class network_device : public device
{
public:
	network_device(struct pci_device *d) : device(d) {}
	~network_device() {}
	
	bool perform_subsystem_initialization() override
	{
		return true;
	}
};

};

struct pci_id virtio_pci_ids[] = 
{
	{ PCI_ID_DEVICE(VIRTIO_VENDOR_ID, PCI_ANY_ID, NULL) },
	{ PCI_ID_DEVICE(VIRTIO_VENDOR_ID2, PCI_ANY_ID, NULL) },
	{}
};

int virtio_probe(struct device *_dev)
{
	struct pci_device *device = (struct pci_device *) _dev;
	unique_ptr<virtio::device> virtio_device;

	if(device->deviceID == QXL_DEVICE_ID_STABLE)
	{
		return -1;
	}

	MPRINTF("Found virtio device at %04x:%02x:%02x:%02x\n",
		device->segment, device->bus, device->device,
		device->function);

	MPRINTF("Device ID %04x\n", device->deviceID);

	auto device_subsystem = pci_get_subsys_id(device);

	switch(device_subsystem)
	{
		case virtio::network_pci_subsys:
			virtio_device = make_unique<virtio::network_device>(device);
			break;
		default:
			return -1;
	}

	size_t cap_off = 0;
	int instance_nr = 0;

	while((cap_off = pci_find_capability(device, PCI_CAP_ID_VENDOR, instance_nr)) != 0)
	{
		instance_nr++;
		printk("cap off %lx\n", cap_off);
		printk("cfg type: %lx\n", pci_read(device, cap_off + virtio::cfg_type_off, sizeof(uint8_t)));
	}

	
	virtio_device->perform_base_virtio_initialization();
	virtio_device->perform_subsystem_initialization();

	return 0;
}

struct driver virtio_driver = 
{
	.name = "virtio",
	.devids = &virtio_pci_ids,
	.probe = virtio_probe
};

extern "C"
int virtio_init(void)
{
	pci_bus_register_driver(&virtio_driver);
	return 0;
}

MODULE_INIT(virtio_init);
MODULE_INSERT_VERSION();
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_AUTHOR("Pedro Falcato");
