/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>

#include <acpi.h>

#include <kernel/acpi.h>
#include <kernel/dev.h>
#include <kernel/log.h>

#include <drivers/pci.h>
#include <drivers/pcie.h>
ACPI_TABLE_MCFG *mcfg = NULL;
struct pcie_allocation *allocations = NULL;

struct bus pcie_bus =
{
	.name = "pcie",
};
int pcie_get_mcfg(void)
{
	ACPI_STATUS st;
	if(ACPI_FAILURE((st = AcpiGetTable("MCFG", 0, (ACPI_TABLE_HEADER**) &mcfg))))
	{
		printf("pcie: MCFG not found - proceeding with conventional pci.\n");
		return 0;
	}
	return 0;
}
bool pcie_is_enabled(void)
{
	return mcfg ? true : false;
}
void pcie_append_allocation(struct pcie_allocation *a)
{
	if(!allocations)
		allocations = a;
	else
	{
		struct pcie_allocation *l = allocations;
		while(l->next)	l = l->next;
		l->next = a;
	}
}
__attribute__((no_sanitize_undefined))
uint64_t pcie_read_device_from_segment(struct pci_device *dev, struct pcie_allocation *alloc, uint16_t off, size_t size)
{
	uint64_t val = -1;
	uintptr_t ptr = (uintptr_t) alloc->address + ((dev->bus - alloc->start_bus) << 20 | dev->device << 15 | 
			dev->function << 12);
	volatile uint64_t *data = (volatile uint64_t *) (ptr + off);
	switch(size)
	{
		case sizeof(uint8_t):
			val = *data & 0xff;
			break;
		case sizeof(uint16_t):
			val = *data & 0xffff;
			break;
		case sizeof(uint32_t):
			val = *data & 0xffffffff;
			break;
		case sizeof(uint64_t):
			val = *data; 
			break;
	}
	return val;
}
__attribute__((no_sanitize_undefined))
void pcie_write_device_from_segment(struct pci_device *dev, struct pcie_allocation *alloc,
uint64_t value, uint16_t off, size_t size)
{
	uintptr_t ptr = (uintptr_t) alloc->address + ((dev->bus - alloc->start_bus) << 20 | dev->device << 15 | 
			dev->function << 12);
	volatile uint64_t *data = (volatile uint64_t *) (ptr + off);
	uint64_t mask = 0;
	switch(size)
	{
		case sizeof(uint8_t):
			mask = 0xff;
			break;
		case sizeof(uint16_t):
			mask = 0xffff;
			break;
		case sizeof(uint32_t):
			mask = 0xffffffff;
			break;
		case sizeof(uint64_t):
			mask = 0xffffffffffffffff;
			break;
		default:
			INFO("pcie", "pcie_write_device_from_segment: Invalid size\n");
			return;
	}
	*data = (*data & ~mask) | value;
}
struct pcie_allocation *pcie_get_allocation_from_dev(struct pci_device *dev)
{
	for(struct pcie_allocation *a = allocations; a; a = a->next)
	{
		if(a->segment != dev->segment)
			continue;
		if(dev->bus < a->start_bus)
			continue;
		if(dev->bus > a->end_bus)
			continue;
		return a;
	}
	return NULL;
}
uint64_t pcie_read(struct pci_device *dev, uint16_t off, size_t size)
{
	struct pcie_allocation *alloc = pcie_get_allocation_from_dev(dev);
	if(!alloc)
		return errno = EIO, (uint64_t) -1;
	return pcie_read_device_from_segment(dev, alloc, off, size);
}
void pcie_write(struct pci_device *dev, uint64_t value, uint16_t off, size_t size)
{
	struct pcie_allocation *alloc = pcie_get_allocation_from_dev(dev);
	if(!alloc)
		return;
	pcie_write_device_from_segment(dev, alloc,value, off, size);
}
uint64_t __pcie_read(uint8_t bus, uint8_t device, uint8_t function, struct pcie_allocation *alloc, 
		    uint16_t off, size_t size)
{
	/* This function is designed for enumeration purposes 
	 * Basically, we pass in a bus, device, function and allocation
	 * and this function creates a stub pci_device on the fly with all those arguments 
	 * and calls pcie_read-device_from_segment
	*/
	struct pci_device dev = {0};
	dev.bus = bus;
	dev.device = device;
	dev.function = function;
	return pcie_read_device_from_segment(&dev, alloc, off, size);
}

void pci_find_supported_capabilities(struct pci_device *dev);

void pcie_enumerate_device(uint8_t bus, uint8_t device, uint8_t function, struct pcie_allocation *alloc)
{
	uint16_t vendor = (uint16_t) __pcie_read(bus, device, function, alloc, 0, sizeof(uint16_t));

	if(vendor == 0xffff) /* Invalid, just skip this device */
		return;
	uint16_t header = (uint16_t) __pcie_read(bus, device, function, alloc, 0xe, sizeof(uint16_t));

	uint8_t pciClass = (uint8_t)(__pcie_read(bus, device, function, alloc, 0xb, sizeof(uint8_t)));
	uint8_t subClass = (uint8_t) __pcie_read(bus, device, function, alloc, 0xa, sizeof(uint8_t));
	uint8_t progIF = (uint8_t) (__pcie_read(bus, device, function, alloc, 0xc, sizeof(uint8_t)));

	// Set up some meta-data
	struct pci_device* dev = zalloc(sizeof(struct pci_device));

	assert(dev != NULL);

	dev->bus = bus;
	dev->function = function;
	dev->device = device;
	dev->segment = alloc->segment;
	dev->vendorID = vendor;
	dev->deviceID = (__pcie_read(bus, device, function, alloc, 0, sizeof(uint32_t)) >> 16);
	dev->pciClass = pciClass;
	dev->subClass = subClass;
	dev->progIF = progIF;
	dev->read = pcie_read;
	dev->write = pcie_write;
	dev->current_power_state = PCI_POWER_STATE_D0;
	dev->type = header & PCI_TYPE_MASK;

	/* Find supported caps and add them to dev */
	pci_find_supported_capabilities(dev);
	/* Set up the pci device's name */
	char name_buf[200] = {0};
	snprintf(name_buf, 200, "pci-%x%x", vendor, dev->deviceID);
	dev->dev.name = strdup(name_buf);
	assert(dev->dev.name);
	
	bus_add_device(&pcie_bus, (struct device*) dev);
	
	/* It's pointless to enumerate subfunctions since functions can't have them */
	/* TODO: Running qemu with -machine q35 returned 0x80 on pci headers with functions != 0
	   Is this a qemu bug or is it our fault?
	*/
	if(function != 0)
		return;
	if(header & 0x80)
	{
		for(int i = 1; i < 8; i++)
		{
			if(__pcie_read(bus, device, i, alloc, 0, sizeof(uint16_t)) == 0xFFFF)
				continue;
			pcie_enumerate_device(bus, device, i, alloc);
		}
	}
}
void pcie_enumerate_devices_in_alloc(struct pcie_allocation *alloc)
{
	for(uint8_t bus = alloc->start_bus; bus < alloc->end_bus; bus++)
	{
		for(uint8_t device = 0; device < 32; device++)
		{
			pcie_enumerate_device(bus, device, 0, alloc);
		}
	}
}
void pcie_enumerate_devices(void)
{
	struct pcie_allocation *alloc = allocations;
	while(alloc)
	{
		pcie_enumerate_devices_in_alloc(alloc);
		alloc = alloc->next;
	}
}
int pcie_init(void)
{
	assert(pcie_is_enabled() == true);
	/* 
	 * If we have PCIe, the MCFG table is passed through acpi to us. 
	 * To read every MCFG allocation, we get the end of the table. The allocations
	 * start there, and there are x number of them
	*/
	ACPI_MCFG_ALLOCATION *alloc = (ACPI_MCFG_ALLOCATION*) (mcfg + 1);
	size_t nr_allocs = (mcfg->Header.Length - sizeof(ACPI_TABLE_MCFG)) / sizeof(ACPI_MCFG_ALLOCATION);
	while(nr_allocs--)
	{
		struct pcie_allocation *allocation = zalloc(sizeof(struct pcie_allocation));
		/* Failing to allocate enough memory here is pretty much a system failure */
		assert(allocation != NULL);
		allocation->address = (volatile void*) alloc->Address + PHYS_BASE;
		allocation->segment = alloc->PciSegment;
		allocation->start_bus = alloc->StartBusNumber;
		allocation->end_bus = alloc->EndBusNumber;

		pcie_append_allocation(allocation);
		++alloc;
	}
	/* Register the PCIe bus */
	bus_register(&pcie_bus);
	/* Finally, enumerate devices */
	pcie_enumerate_devices();
	return 0;
}
struct pci_device *get_pciedev_from_classes(uint8_t pciclass, uint8_t subclass, uint8_t progif)
{
	struct device *d = pcie_bus.devs;
	while(d)
	{
		struct pci_device *pci = (struct pci_device *) d;
		if(pci->pciClass == pciclass && pci->subClass == subclass && pci->progIF == progif)
			return pci;
		d = d->next;
	}
	return NULL;
}
struct pci_device *get_pciedev_from_vendor_device(uint16_t deviceid, uint16_t vendorid)
{
	struct device *d = pcie_bus.devs;
	while(d)
	{
		struct pci_device *pci = (struct pci_device *) d;
		if(pci->deviceID == deviceid && pci->vendorID == vendorid)
			return pci;
		d = d->next;
	}
	return NULL;
}
