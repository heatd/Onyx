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

#include <pci/pci.h>

/* For QXL_DEVICE_ID_STABLE */
#include "../qxl/qxl_dev.h"

#define MPRINTF(...)	printf("virtio: " __VA_ARGS__)

#define VIRTIO_VENDOR_ID	0x1af4
#define VIRTIO_VENDOR_ID2	0x1b36

struct pci_id virtio_pci_ids[] = 
{
	{ PCI_ID_DEVICE(VIRTIO_VENDOR_ID, PCI_ANY_ID) },
	{ PCI_ID_DEVICE(VIRTIO_VENDOR_ID2, PCI_ANY_ID) },
	{0}
};

int virtio_probe(struct device *_dev)
{
	struct pci_device *device = (struct pci_device *) _dev;
	
	if(device->deviceID == QXL_DEVICE_ID_STABLE)
	{
		return -1;
	}

	MPRINTF("Found virtio device at %04x:%02x:%02x:%02x\n",
		device->segment, device->bus, device->device,
		device->function);

	MPRINTF("Device ID %04x\n", device->deviceID);

	return 0;
}

struct driver virtio_driver = 
{
	.name = "virtio",
	.devids = &virtio_pci_ids,
	.probe = virtio_probe
};

int virtio_init(void)
{
	pci_bus_register_driver(&virtio_driver);
	return 0;
}

DRIVER_INIT(virtio_init);