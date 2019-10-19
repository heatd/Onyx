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

#include <onyx/acpi.h>
#include <onyx/dev.h>
#include <onyx/log.h>

#include <pci/pci.h>
#include <pci/pcie.h>
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

struct pcie_address
{
	uint8_t bus;
	uint8_t device;
	uint8_t function;
	struct pcie_allocation *alloc;
	uint16_t offset;
};

static inline uint32_t __pcie_config_read_dword(struct pcie_address addr)
{
	uintptr_t ptr = (uintptr_t) addr.alloc->address +
		((addr.bus - addr.alloc->start_bus) << 20 | addr.device << 15 | 
			addr.function << 12);
	volatile uint32_t *data = (volatile uint32_t *) (ptr + addr.offset);

	return *data;
}

static inline void __pcie_config_write_dword(struct pcie_address addr, uint32_t data)
{
	uintptr_t ptr = (uintptr_t) addr.alloc->address +
		((addr.bus - addr.alloc->start_bus) << 20 | addr.device << 15 | 
			addr.function << 12);
	volatile uint32_t *uptr = (volatile uint32_t *) (ptr + addr.offset);

	*uptr = data;
}

void __pcie_config_write_byte(struct pcie_address addr, uint8_t data)
{
	uint16_t aligned_offset = addr.offset & -4;
	uint16_t write_offset = addr.offset - aligned_offset;
	uint16_t write_mask = 0xff << (write_offset * 8);
	addr.offset = aligned_offset;
	uint32_t dword = __pcie_config_read_dword(addr);

	dword = (dword & ~write_mask) | (uint32_t) data << (write_offset * 8);

	__pcie_config_write_dword(addr, dword);
}

uint8_t __pcie_config_read_byte(struct pcie_address addr)
{
	uint16_t aligned_offset = addr.offset & -4;
	uint16_t byte_shift = addr.offset - aligned_offset;
	addr.offset = aligned_offset;
	uint32_t dword = __pcie_config_read_dword(addr);

	return ((dword >> (byte_shift * 8)) & 0xff);
}

uint16_t __pcie_config_read_word(struct pcie_address addr)
{
	uint16_t ret = 0;
        uint16_t aligned_off = addr.offset & -4;
	uint16_t byte_shift = addr.offset - aligned_off;

	addr.offset = aligned_off;

	uint32_t dword = __pcie_config_read_dword(addr);

	ret = (dword >> (byte_shift * 8));

	return ret;
}

void __pcie_config_write_word_aligned(struct pcie_address addr, uint16_t data)
{
	uintptr_t ptr = (uintptr_t) addr.alloc->address +
		((addr.bus - addr.alloc->start_bus) << 20 | addr.device << 15 | 
			addr.function << 12);
	volatile uint16_t *uptr = (volatile uint16_t *) (ptr + addr.offset);

	*uptr = data;
}

void __pcie_config_write_word(struct pcie_address addr, uint16_t data)
{
	uint8_t aligned_offset = addr.offset & -4;
	uint8_t bshift = addr.offset - aligned_offset;

	if(aligned_offset == addr.offset)
	{
		/* For some reason, we need to do this for linux's
		 * i915 driver's GVT to accept PCI config space writes
		 * I guess this is an optimization too
		*/
		__pcie_config_write_word_aligned(addr, data);
		return;
	}

	uint32_t byte_mask = (uint32_t) 0xffff << (bshift * 8);
	addr.offset = aligned_offset;
	uint32_t dword = __pcie_config_read_dword(addr);
	dword = (dword & ~byte_mask) | (data << (bshift * 8));
	__pcie_config_write_dword(addr, dword);
}

uint64_t pcie_read_device_from_segment(struct pci_device *dev, struct pcie_allocation *alloc, uint16_t off, size_t size)
{
	uint64_t val = -1;

	struct pcie_address addr;
	addr.alloc = alloc;
	addr.bus = dev->bus;
	addr.device = dev->device;
	addr.function = dev->function;
	addr.offset = off;

	switch(size)
	{
		case sizeof(uint8_t):
			val = __pcie_config_read_byte(addr);
			break;
		case sizeof(uint16_t):
			val = __pcie_config_read_word(addr);
			break;
		case sizeof(uint32_t):
			val = __pcie_config_read_dword(addr);
			break;
		case sizeof(uint64_t):
			val = __pcie_config_read_dword(addr);
			addr.offset += 4;
			val |= (uint64_t) __pcie_config_read_dword(addr) << 32;
			break;
	}
	return val;
}

void pcie_write_device_from_segment(struct pci_device *dev, struct pcie_allocation *alloc,
uint64_t value, uint16_t off, size_t size)
{
	struct pcie_address addr;
	addr.alloc = alloc;
	addr.bus = dev->bus;
	addr.device = dev->device;
	addr.function = dev->function;
	addr.offset = off;

	switch(size)
	{
		case sizeof(uint8_t):
			__pcie_config_write_byte(addr, (uint8_t) value);
			break;
		case sizeof(uint16_t):
			__pcie_config_write_word(addr, (uint16_t) value);
			break;
		case sizeof(uint32_t):
			__pcie_config_write_dword(addr, (uint32_t) value);
			break;
		case sizeof(uint64_t):
			__pcie_config_write_byte(addr, (uint32_t) value);
			addr.offset += 4;
			__pcie_config_write_dword(addr, (uint32_t) (value >> 32));
			break;
		default:
			INFO("pcie", "pcie_write_device_from_segment: Invalid size\n");
			return;
	}
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
	for(int i = 1; i < 8; i++)
	{
		if(__pcie_read(bus, device, i, alloc, 0, sizeof(uint16_t)) == 0xFFFF)
			continue;
		pcie_enumerate_device(bus, device, i, alloc);
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

		unsigned int nr_buses = alloc->EndBusNumber - alloc->StartBusNumber;
		size_t size = nr_buses << 20;

		allocation->address = mmiomap((void *) alloc->Address, size,
			VM_WRITE | VM_NOEXEC | VM_NOCACHE);
		
		assert(allocation->address != NULL);

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
	assert(acpi_get_irq_routing_info(&pcie_bus) == 0);
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

struct pci_device *get_pciedev(struct pci_device_address *addr)
{
	struct device *d = pcie_bus.devs;
	while(d)
	{
		struct pci_device *pci = (struct pci_device *) d;
		if(pci->segment == addr->segment && pci->bus == addr->bus && pci->device == 
		   addr->device && pci->function == addr->function)
			return pci;
		d = d->next;
	}
	return NULL;
}
