/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _PCIE_H
#define _PCIE_H

#include <stdbool.h>

struct pcie_allocation
{
	/* Mappings of the pcie allocation's configuration address space 
	 * Generally, it's phys_address + PHYS_BASE 
	*/
	volatile void *address;
	/* Segment number */
	uint16_t segment;
	/* Start and end buses */
	uint8_t start_bus, end_bus;
	struct pcie_allocation *next;
};

struct pci_device_address;

int pcie_get_mcfg(void);
bool pcie_is_enabled(void);
int pcie_init(void);

struct pci_device *get_pciedev(struct pci_device_address *addr);

#endif
