/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <string.h>

#include <kernel/compiler.h>
#include <kernel/log.h>
#include <kernel/acpi.h>
#include <kernel/panic.h>

#include <drivers/pci.h>

const uint16_t CONFIG_ADDRESS = 0xCF8;
const uint16_t CONFIG_DATA = 0xCFC;


/* Identify the Device type with the headerType as an argument
    Possible return values are "PCI Device", "PCI-to-PCI Bridge" or "CardBus Bridge"
    Returns a pointer to a device type string
    Returns "Invalid" on error
*/
const char* IdentifyDeviceType(uint16_t headerType)
{
	if(headerType == 0)
		return "PCI Device";
	else if(headerType == 1)
		return "PCI-to-PCI Bridge";
	else if(headerType == 2)
		return "CardBus Bridge";

	return "Invalid";
}
uint16_t pci_config_read_word (uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset)
{
        uint32_t address;
	uint32_t lbus  = (uint32_t)bus;
	uint32_t lslot = (uint32_t)slot;
	uint32_t lfunc = (uint32_t)func;
	uint16_t tmp = 0;

	/* create configuration address as per Figure 1 */
	address = (uint32_t)((lbus << 16) | (lslot << 11) |
                     (lfunc << 8) | (offset & 0xfc) | ((uint32_t)0x80000000));

	/* write out the address */
	outl (CONFIG_ADDRESS, address);
	/* read in the data */
	/* (offset & 2) * 8) = 0 will choose the first word of the 32 bits register */
	tmp = (uint16_t)((inl (CONFIG_DATA) >> ((offset & 2) * 8)) & 0xffff);
	return tmp;
}
uint32_t pci_config_read_dword (uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset)
{
	uint32_t address;
	uint32_t lbus  = (uint32_t)bus;
	uint32_t lslot = (uint32_t)slot;
	uint32_t lfunc = (uint32_t)func;
	uint32_t tmp = 0;

	/* create configuration address as per Figure 1 */
	address = (uint32_t)((lbus << 16) | (lslot << 11) |
                     (lfunc << 8) | (offset & 0xfc) | ((uint32_t)0x80000000));

	/* write out the address */
	outl (CONFIG_ADDRESS, address);
	/* read in the data */
	tmp = (uint32_t)((inl (CONFIG_DATA)));
	return tmp;
}
void pci_write_dword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t data)
{
	uint32_t address;
	uint32_t lbus  = (uint32_t)bus;
	uint32_t lslot = (uint32_t)slot;
	uint32_t lfunc = (uint32_t)func;

	/* create configuration address as per Figure 1 */
	address = (uint32_t)((lbus << 16) | (lslot << 11) |
		  (lfunc << 8) | (offset & 0xfc) | ((uint32_t)0x80000000));

	/* write out the address */
	outl (CONFIG_ADDRESS, address);
	/* read in the data */
	outl(CONFIG_DATA, data);
}
void pci_write_word(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint16_t data)
{
	uint32_t address;
	uint32_t lbus  = (uint32_t)bus;
	uint32_t lslot = (uint32_t)slot;
	uint32_t lfunc = (uint32_t)func;

	/* create configuration address as per Figure 1 */
	address = (uint32_t)((lbus << 16) | (lslot << 11) |
		  (lfunc << 8) | (offset & 0xfc) | ((uint32_t)0x80000000));

	/* write out the address */
	outl (CONFIG_ADDRESS, address);
	/* read in the data */
	outw(CONFIG_DATA, data);
}
struct pci_device *linked_list = NULL;
struct pci_device* last = NULL;
void* pci_check_function(uint8_t bus, uint8_t device, uint8_t function)
{
	// Get vendorID
	uint16_t vendorID = (uint16_t)(pci_config_read_dword(bus, device, function,0) & 0x0000ffff);
	if(vendorID == 0xFFFF) //Invalid function
		return NULL;
	// Get device ID
	uint16_t deviceID = (pci_config_read_dword(bus, device, function,0) >> 16);
	// Get Device Class
	uint8_t pciClass = (uint8_t)(pci_config_read_word(bus, device, function , 0xA)>>8);
	// Get Device SubClass
	uint8_t subClass = (uint8_t)pci_config_read_word(bus,device, function, 0xB);
	// Get ProgIF
	uint8_t progIF = (uint8_t)(pci_config_read_word(bus, device, function,0xC)>>8);
	// Set up the meta-data
	struct pci_device* dev = malloc(sizeof(struct pci_device));
	if(!dev)
		panic("pci: early unrecoverable oom\n");
	memset(dev, 0 , sizeof(struct pci_device));
	dev->slot = bus;
	dev->function = function;
	dev->device = device;
	dev->vendorID = vendorID;
	dev->deviceID = deviceID;
	dev->pciClass = pciClass;
	dev->subClass = subClass;
	dev->progIF = progIF;
	// Put it on the linked list
	last->next = dev;
	last = dev;

	return dev;

}
void pci_check_devices()
{
	for(uint16_t slot = 0; slot < 256; slot++)
	{
		for(uint16_t device = 0; device < 32; device++)
		{
			//uint8_t function = 0;
			// Get vendor
			uint16_t vendor = (uint16_t)(pci_config_read_dword(slot, device, 0,0) & 0x0000ffff);

			if(vendor == 0xFFFF) //Invalid, just skip this device
				break;

			//INFO("pci", "Found a device at slot %d, device %d, function %d: ",slot,device,0);

			// Check the vendor against a bunch of mainstream hardware developers
			//printf("Vendor: %s\n", IdentifyCommonVendors(vendor));
			//printf("DeviceID: %X\n", pci_config_read_dword(slot, device, 0,0) >> 16);

			// Get header type
			uint16_t header = (uint16_t)(pci_config_read_word(slot, device, 0,0xE));

			//printf("Device type: %s\n",IdentifyDeviceType(header & 0x7F));
			uint8_t pciClass = (uint8_t)(pci_config_read_word(slot, device, 0 , 0xA)>>8);
			uint8_t subClass = (uint8_t)pci_config_read_word(slot,device, 0, 0xB);
			uint8_t progIF = (uint8_t)(pci_config_read_word(slot, device, 0,0xC)>>8);

			// Set up some meta-data
			struct pci_device* dev = malloc(sizeof(struct pci_device));
			if(!dev)
				panic("pci: early unrecoverable oom\n");
			memset(dev, 0 , sizeof(struct pci_device));
			dev->slot = slot;
			dev->function = 0;
			dev->device = device;
			dev->vendorID = vendor;
			dev->deviceID = (pci_config_read_dword(slot, device, 0,0) >> 16);
			dev->pciClass = pciClass;
			dev->subClass = subClass;
			dev->progIF = progIF;
			// If last is not NULL (it is at first), set this device as the last node's next
			if(likely(last))
				last->next = dev;
			else
				linked_list = dev;

			last = dev;
			if(header & 0x80)
			{
				for(int i = 1; i < 8;i++)
				{
					struct pci_device* dev = pci_check_function(slot, device, i);
					if(!dev)
						continue;

				}
			}
		}
	}
}
pcibar_t* pci_get_bar(uint8_t slot, uint8_t device, uint8_t function, uint8_t barindex)
{
	uint8_t offset = 0x10 + 0x4 * barindex;
	uint32_t i = pci_config_read_dword(slot, device,function,offset);
	pcibar_t* pcibar = malloc(sizeof(pcibar_t));
	if(!pcibar)
		return NULL;
	pcibar->address = i & 0xFFFFFFF0;
	pcibar->isIO = i & 1;
	if(i & 1)
		pcibar->address = i & 0xFFFFFFFC;
	pcibar->isPrefetchable = i & 4;
	pci_write_dword(slot, device, function, offset, 0xFFFFFFFF);
	size_t size = (~((pci_config_read_dword(slot, device,function,offset) & 0xFFFFFFF0))) + 1;
	pcibar->size = size;
	pci_write_dword(slot, device,function,offset, i);
	return pcibar;
}
uint16_t pci_get_intn(uint8_t slot, uint8_t device, uint8_t function)
{
	return acpi_get_irq_routing_for_dev(slot, device, function);
}
void pci_init()
{
	//LOG("pci", "Initializing the PCI driver\n");
	//LOG("pci", "Enumerating PCI devices\n");
	pci_check_devices();
}
struct pci_device *get_pcidev_from_vendor_device(uint16_t deviceid, uint16_t vendorid)
{
	for(struct pci_device *i = linked_list; i;i = i->next)
	{
		if(i->deviceID == deviceid && i->vendorID == vendorid)
			return i;
	}
	return NULL;
}
struct pci_device *get_pcidev_from_classes(uint8_t class, uint8_t subclass, uint8_t progif)
{
	for(struct pci_device *i = linked_list; i;i = i->next)
	{
		if(i->pciClass == class && i->subClass == subclass && i->progIF == progif)
			return i;
	}
	return NULL;
}
void pci_set_barx(uint8_t slot, uint8_t device, uint8_t function, uint8_t index, uint32_t address, uint8_t is_io, uint8_t is_prefetch)
{
	uint32_t bar = address | is_io | (is_prefetch << 2);
	pci_write_dword(slot, device, function, PCI_BARx(index), bar);
}
/* All the PCI drivers' headers */
#include <drivers/e1000.h>
#include <drivers/ata.h>
pci_driver_t pci_drivers[] =
{
	{E1000_DEV, INTEL_VEND, CLASS_NETWORK_CONTROLLER, 0, 0, PCI_DRIVER_SPECIFIC, e1000_init},
	{E1000_I217, INTEL_VEND, CLASS_NETWORK_CONTROLLER, 0, 0, PCI_DRIVER_SPECIFIC, e1000_init},
	{E1000_82577LM, INTEL_VEND, CLASS_NETWORK_CONTROLLER, 0, 0, PCI_DRIVER_SPECIFIC, e1000_init},
	{0, 0, CLASS_MASS_STORAGE_CONTROLLER, 1, 0, PCI_DRIVER_GENERIC, ata_init},
};

const size_t pci_driver_array_entries = sizeof(pci_drivers) / sizeof(pci_driver_t);
void pci_initialize_drivers()
{
	for(size_t i = 0; i < pci_driver_array_entries; i++)
	{
		if(pci_drivers[i].driver_type == PCI_DRIVER_GENERIC)
		{
			struct pci_device *dev = get_pcidev_from_classes(pci_drivers[i].pciClass, pci_drivers[i].subClass, pci_drivers[i].progIF);
			if(!dev)
				continue;
			pci_drivers[i].cb(dev);
		}	
		else
		{
			struct pci_device *dev = get_pcidev_from_vendor_device(pci_drivers[i].deviceID, pci_drivers[i].vendorID);
			if(!dev)
				continue;
			pci_drivers[i].cb(dev);
		}
			
	}
}