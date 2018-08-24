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
#include <onyx/log.h>
#include <onyx/video/edid.h>

#include <pci/pci.h>

#define MPRINTF(...)	printk("ihdgpu: " __VA_ARGS__)

#define INTEL_VENDOR_ID	0x8086

//static_assert(sizeof(struct edid_data) == 128, "bad edid data");

struct pci_id ihdgpu_pci_ids[] = 
{
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x5917) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x5916) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x5912) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x5902) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x1606) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x1612) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x1616) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x161e) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x1626) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x1902) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x1906) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x1912) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x191b) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x191d) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x191e) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x1921) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x591d) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x0a16) },
	{0}
};

int ihdgpu_probe(struct device *dev)
{
	struct pci_device *device = (struct pci_device *) dev;
	MPRINTF("Found suitable Intel HD Graphics GPU at %04x:%02x:%02x:%02x\n"
		"ID %04x:%04x\n", device->segment, device->bus, device->device,
		device->function, device->vendorID, device->deviceID);
	
	if(pci_enable_device(device) < 0)
	{
		ERROR("ihdgpu", "Could not enable device\n");
		return -1;
	}

	void *device_registers = pci_map_bar(device, 0);
	
	if(device_registers == NULL)
	{
		ERROR("ihdgpu", "Could not map device registers\n");
		return -1;
	}

	void *gpu_memory = pci_map_bar(device, 2);

	if(gpu_memory == NULL)
	{
		ERROR("ihdgpu", "Could not map GPU memory\n");
		return -1;
	}

	if(pci_reset_device(device) < 0)
	{
		printk("Could not reset device\n");
	}

	return 0;

}

struct driver ihdgpu_driver = 
{
	.name = "ihdgpu",
	.devids = &ihdgpu_pci_ids,
	.probe = ihdgpu_probe
};

int ihdgpu_init(void)
{
	printk("Registering ihdgpu driver!\n");
	pci_bus_register_driver(&ihdgpu_driver);
	return 0;
}

DRIVER_INIT(ihdgpu_init);