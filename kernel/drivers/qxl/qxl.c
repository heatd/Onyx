/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdatomic.h>
#include <stdio.h>
#include <assert.h>

#include <onyx/driver.h>
#include <onyx/dev.h>
#include <onyx/acpi.h>
#include <onyx/dpc.h>

#include <pci/pci.h>

#include "qxl_dev.h"
#include "qxl.h"

#define MPRINTF(...)	printf("qxl: " __VA_ARGS__)

#define QXL_VENDOR_ID	0x1b36

struct pci_id qxl_pci_ids[] = 
{
	{ PCI_ID_DEVICE(QXL_VENDOR_ID, QXL_DEVICE_ID_STABLE) },
	{0}
};

int qxl_check_rom(struct qxl_device *device)
{
	struct qxl_rom *rom = device->rom;

	if(rom->magic != QXL_ROM_MAGIC)
	{
		MPRINTF("Bad ROM checksum %x\n", rom->magic);
		return -1;
	}

	return 0;
}

int qxl_check_ram(struct qxl_device *device)
{
	if(device->ram_header->magic != QXL_RAM_MAGIC)
	{
		MPRINTF("Bad RAM checksum %x\n", device->ram_header->magic);
		return -1;
	}

	return 0;
}

void qxl_reset(struct qxl_device *device)
{
	outb(device->iorange_bar.address, 0);
}

void qxl_eoi(struct qxl_device *device)
{
	outb(device->iorange_bar.address + QXL_IO_UPDATE_IRQ, 0);
}

irqstatus_t qxl_irq_handler(struct irq_context *context, void *cookie)
{
	struct qxl_device *device = cookie;
	uint32_t pending;

	pending = atomic_exchange(&device->ram_header->int_pending, 0UL);

	if(pending == 0)
	{
		/* No pending IRQ, wrong device */
		return IRQ_UNHANDLED;
	}

	atomic_fetch_add(&device->irq_count, 1);

	/* TODO: Handle IRQs */

	device->ram_header->int_mask = QXL_INTERRUPT_MASK;
	
	qxl_eoi(device);
	return IRQ_HANDLED;
}

int qxl_init_irq(struct qxl_device *device)
{
	uint16_t irq = pci_get_intn(device->device);
	if(irq == UINT16_MAX)
		return -1;

	if(install_irq(irq, qxl_irq_handler, &device->device->dev, IRQ_FLAG_REGULAR, device) < 0)
		return -1;

	device->ram_header->int_mask = QXL_INTERRUPT_MASK;
	return 0;
}

int qxl_init_device(struct qxl_device *device)
{
	/* Get the PCI bars */
	pci_get_bar(device->device, QXL_VRAM_BAR, &device->vram_bar);
	pci_get_bar(device->device, QXL_ROM_BAR, &device->rom_bar);
	pci_get_bar(device->device, QXL_IOBASE_BAR, &device->iorange_bar);
	
	if((device->vram_mapping = pci_map_bar(device->device, QXL_VRAM_BAR)) == NULL)
	{
		MPRINTF("Could not map vram\n");
		return -1;
	}

	int sbar = QXL_SURFACE64_BAR;
	/* First try the 64-bit BAR */
	pci_get_bar(device->device, QXL_SURFACE64_BAR, &device->surface_bar);

	if(device->surface_bar.size == 0)
	{
		sbar = QXL_SURFACE_BAR;
		/* If it doesn't exist, use the 32-bit one */
		pci_get_bar(device->device, QXL_SURFACE_BAR, &device->surface_bar);
	}

	/* TODO: destroy all the mappings done when I get that done in the
	 * virtual memory manager */
	if((device->surface_mapping = pci_map_bar(device->device, sbar)) == NULL)
	{
		MPRINTF("Could not map surface\n");
		return -1;
	}

	if((device->rom = pci_map_bar(device->device, QXL_ROM_BAR)) == NULL)
	{
		MPRINTF("Could not map ROM\n");
		return -1;
	}

	if(qxl_check_rom(device) < 0)
		return -1;

	device->ram_header = (void *) ((char *) device->vram_mapping +
		device->rom->ram_header_offset);
	
	if(qxl_check_ram(device) < 0)
		return -1;

	qxl_reset(device);

	qxl_init_irq(device);

	qxl_list_modes(device);
	return 0;
}

int qxl_probe(struct device *_dev)
{
	struct pci_device *device = (struct pci_device *) _dev;

	MPRINTF("Found qxl device at %04x:%02x:%02x:%02x\n",
		device->segment, device->bus, device->device,
		device->function);

	if(pci_enable_device(device) < 0)
	{
		MPRINTF("error: Could not enable pci device\n");
		return -1;
	}

	struct qxl_device *qxldevice = zalloc(sizeof(*qxldevice));
	if(!qxldevice)
		return -1;
	qxldevice->device = device;
	device->dev.priv = qxldevice;

	if(qxl_init_device(qxldevice) < 0)
	{
		free(qxldevice);
		device->dev.priv = NULL;
		return -1;
	}

	return 0;
}

struct driver qxl_driver = 
{
	.name = "qxl",
	.devids = &qxl_pci_ids,
	.probe = qxl_probe
};

int qxl_init(void)
{
	pci_bus_register_driver(&qxl_driver);
	return 0;
}

DRIVER_INIT(qxl_init);