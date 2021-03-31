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
#include <onyx/cpu.h>

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
		  hrtime_t timeout, bool clear)
{
	hrtime_t t0 = clocksource_get_time();
	
	while(true)
	{
		/* If the time is up, return a timeout */
		if(clocksource_get_time() - t0 >= timeout)
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

		/* TODO: Use a sleep when we implement clock events */
		cpu_relax();
	}

	return -ETIMEDOUT;
}

int igd_enable_display_engine_skl(struct igpu_device *dev);
int igd_enable_display_engine_hsw(struct igpu_device *dev);

struct igpu_driver_data igpu_skl_priv = {
	.has_gmch_display = false,
	.enable_power = igd_enable_power_skylake,
	.enable_display_engine = igd_enable_display_engine_skl,
	.architecture = INTEL_ARCH_SKYLAKE
};

struct igpu_driver_data igpu_haswell_priv = 
{
	.has_gmch_display = false,
	.enable_power = igd_enable_power_haswell,
	.enable_display_engine = igd_enable_display_engine_hsw,
	.architecture = INTEL_ARCH_HASWELL
};

struct igpu_driver_data igpu_haswell_priv_ult = 
{
	.has_gmch_display = false,
	.enable_power = igd_enable_power_haswell,
	.enable_display_engine = igd_enable_display_engine_hsw,
	.architecture = INTEL_ARCH_HASWELL,
	.extra_flags = INTEL_FLAG_ULT
};

struct pci_id ihdgpu_pci_ids[] = 
{
	{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x5917, &igpu_skl_priv) },
	//{ PCI_ID_DEVICE(INTEL_VENDOR_ID, 0x0a16, &igpu_haswell_priv_ult) },
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
	/* TODO: Replace free(d) with actual device destruction */
	struct pci_device *device = (struct pci_device *) dev;
	MPRINTF("Found suitable Intel HD Graphics GPU at %04x:%02x:%02x:%02x\n"
		"ID %04x:%04x\n", device->segment, device->bus, device->device,
		device->function, device->vendorID, device->deviceID);
	
	struct igpu_device *d = (igpu_device *) zalloc(sizeof(*d));
	if(!d)
		return -1;

	if(pci_enable_device(device) < 0)
	{
		ERROR("ihdgpu", "Could not enable device\n");
		free(d);
		return -1;
	}

	void *device_registers = pci_map_bar(device, 0, VM_NOCACHE);
	
	if(device_registers == NULL)
	{
		ERROR("ihdgpu", "Could not map device registers\n");
		free(d);
		return -1;
	}

	void *gpu_memory = pci_map_bar(device, 2, VM_WC);

	if(gpu_memory == NULL)
	{
		ERROR("ihdgpu", "Could not map GPU memory\n");
		free(d);
		return -1;
	}

	if(pci_reset_device(device) < 0)
	{
		if(errno != ENOTSUP)
		{
			printf("igpu: Could not reset device\n");
			free(d);
			return -1;
		}
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

	if(igd_init_pipes(d) < 0)
	{
		printk("igd: igd_init_pipes failed\n");
		free(d);
		return -1;
	}

	if(igd_init_transcoders(d) < 0)
	{
		printk("igd: igd_init_transcoders failed\n");
		free(d);
		return -1;
	}

	if(igd_init_primary_planes(d) < 0)
	{
		printk("igd: igd_init_primary_planes failed\n");
		free(d);
		return -1;
	}

	igd_enable_display_engine_skl(d);

	igd_query_displays(d);

	if(d->lfp_data)
	{
		/* If eDP/LVDS is present, connect DDI_A to PIPE_A to TRANS_eDP */
		struct igd_displayport *ddia = d->dports[DDI_A];
		
		ddia->pipe = d->pipes[PIPE_A];
		ddia->pipe->transcoder = d->transcoders[TRANS_EDP];

		igd_update_pipe_mode(ddia->pipe, d);
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
	pci_bus_register_driver(&ihdgpu_driver);
	return 0;
}

MODULE_INIT(ihdgpu_init);
MODULE_INSERT_VERSION();
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_AUTHOR("Pedro Falcato");
