/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _KERNEL_PCI_H
#define _KERNEL_PCI_H
#include <stdint.h>
#include <kernel/portio.h>

typedef struct PCIDevice
{
	uint16_t deviceID, vendorID;
	char* vendor_string, *function_string;
	uint8_t slot, device, function;
	uint8_t pciClass, subClass, progIF;
	struct PCIDevice* next;
}PCIDevice;
typedef struct
{
	uint32_t address;
	_Bool isPrefetchable;
	_Bool isIO;
	size_t size;
}pcibar_t;
void pci_init();
uint16_t pci_config_read_word (uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset);
void pci_check_devices();
uint32_t pci_config_read_dword (uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset);
const char* pci_identify_common_vendors(uint16_t vendorID);
const char* pci_identify_device_type(uint16_t headerType);
const char* pci_identify_device_function(uint8_t pciClass, uint8_t subClass, uint8_t progIF);
pcibar_t* pci_get_bar(uint8_t slot, uint8_t device, uint8_t function, uint8_t barindex);
uint16_t pci_get_intn(uint8_t slot, uint8_t device, uint8_t function);
PCIDevice *get_pcidev_from_vendor_device(uint16_t deviceid, uint16_t vendorid);
PCIDevice *get_pcidev_from_classes(uint8_t class, uint8_t subclass, uint8_t progif);
void pci_write_dword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t data);
void pci_write_word(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint16_t data);
void pci_set_barx(uint8_t slot, uint8_t device, uint8_t function, uint8_t index, uint32_t address, uint8_t is_io, uint8_t is_prefetch);
#define PCI_BAR0 0x10
#define PCI_BARx(index) (PCI_BAR0 + 0x4 * index)
#define PCI_INTN 0x44
#define PCI_COMMAND 0x4
#endif
