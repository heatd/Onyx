/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <assert.h>
#include <errno.h>

#include <onyx/timer.h>
#include <onyx/driver.h>
#include <onyx/dev.h>
#include <onyx/acpi.h>
#include <onyx/log.h>
#include <onyx/video/edid.h>

#include <pci/pci.h>

#include "intel_regs.h"
#include "igpu_drv.h"
#include "igd_opregion.h"

#define INTEL_VENDOR_ID	0x8086

static_assert(sizeof(struct edid_data) == 128, "bad edid data");

uint32_t igpu_mmio_read(struct igpu_device *dev, uint32_t offset)
{
	offset /= 4;
	volatile uint32_t *mmio_regs = (volatile uint32_t *) dev->mmio_regs;

	return mmio_regs[offset];
}

void igpu_mmio_write(struct igpu_device *dev, uint32_t offset, uint32_t data)
{
	volatile uint32_t *mmio_regs = (volatile uint32_t *) dev->mmio_regs;

	mmio_regs[offset / 4] = data;
}

int igpu_wait_bit(struct igpu_device *dev, uint32_t reg, uint32_t mask,
		  unsigned long timeout, bool clear)
{
	uint64_t last = get_tick_count();
	
	while(true)
	{
		/* If the time is up, return a timeout */
		if(last + timeout < get_tick_count())
			return -ETIMEDOUT;
		if(clear)
		{
			if((igpu_mmio_read(dev, reg) & mask) == 0)
				return 0;
		}
		else
		{
			if((igpu_mmio_read(dev, reg) & mask) == mask)
				return 0;
		}

		sched_yield();
	}

	return -ETIMEDOUT;
}

struct igpu_driver_data igpu_default_priv = {
	.has_gmch_display = false
};

struct pci_id ihdgpu_pci_ids[] = 
{
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x5917, &igpu_default_priv) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x5916, &igpu_default_priv) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x5912, &igpu_default_priv) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x5902, &igpu_default_priv) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x1606, &igpu_default_priv) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x1612, &igpu_default_priv) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x1616, &igpu_default_priv) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x161e, &igpu_default_priv) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x1626, &igpu_default_priv) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x1902, &igpu_default_priv) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x1906, &igpu_default_priv) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x1912, &igpu_default_priv) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x191b, &igpu_default_priv) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x191d, &igpu_default_priv) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x191e, &igpu_default_priv) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x1921, &igpu_default_priv) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x591d, &igpu_default_priv) },
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x0a16, &igpu_default_priv) },
	{0}
};

int igpu_read_edid(struct igpu_device *dev)
{
	uint32_t gmbus2 = igpu_mmio_read(dev, GMBUS2);
	printk("gmbus2: %x\n", gmbus2);
	errno = EIO;
	return -1;
}

int ihdgpu_probe(struct device *dev)
{
	struct pci_device *device = (struct pci_device *) dev;
	MPRINTF("Found suitable Intel HD Graphics GPU at %04x:%02x:%02x:%02x\n"
		"ID %04x:%04x\n", device->segment, device->bus, device->device,
		device->function, device->vendorID, device->deviceID);
	
	struct igpu_device *d = zalloc(sizeof(*d));
	if(!d)
		return -1;

	if(pci_enable_device(device) < 0)
	{
		ERROR("ihdgpu", "Could not enable device\n");
		free(d);
		return -1;
	}

	void *device_registers = pci_map_bar(device, 0);
	
	if(device_registers == NULL)
	{
		ERROR("ihdgpu", "Could not map device registers\n");
		free(d);
		return -1;
	}

	void *gpu_memory = pci_map_bar(device, 2);

	if(gpu_memory == NULL)
	{
		ERROR("ihdgpu", "Could not map GPU memory\n");
		free(d);
		return -1;
	}

	if(pci_reset_device(device) < 0)
	{
		printf("igpu: Could not reset device\n");
	}

	d->device = device;
	d->mmio_regs = (volatile void *) device_registers;
	d->gpu_memory = (volatile void *) gpu_memory;

	if(igd_enable_power(d) < 0)
	{
		printk("igd_enable_power failed\n");
		free(d);
		return -1;
	}

	if(igpu_i2c_init(d) < 0)
	{
		perror("igpu_i2c_init failed");
		free(d);
		return -1;
	}

	if(igd_opregion_init(d) < 0)
	{
		printk("igpu: igd_opregion_init failed.\n");
		free(d);
		return -1;
	}

	if(igd_init_displayport(d) < 0)
	{
		printk("igd: igd_init_displayport failed\n");
		free(d);
		return -1;
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