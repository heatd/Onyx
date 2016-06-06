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
#ifndef _PCI_H
#define _PCI_H
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
	void pci_init();
	uint16_t pci_config_read_word (uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset);
	void pci_check_devices();
	uint32_t pci_config_read_dword (uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset);
	const char* pci_identify_common_vendors(uint16_t vendorID);
	const char* pci_identify_device_type(uint16_t headerType);
	const char* pci_identify_device_function(uint8_t pciClass, uint8_t subClass, uint8_t progIF);

	typedef struct
	{
		uint32_t address;
		_Bool isPrefetchable;
		_Bool isIO;
	}pcibar_t;

#endif
