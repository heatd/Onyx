/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ahci.h>

#include <kernel/log.h>
#include <kernel/compiler.h>
#include <kernel/module.h>
#include <kernel/vmm.h>

#include <drivers/pci.h>

MODULE_AUTHOR("Pedro Falcato");
MODULE_LICENSE(MODULE_LICENSE_GPL2);
MODULE_INSERT_VERSION();

#define MPRINTF(...) printf("ahci: "__VA_ARGS__)

static PCIDevice *ahci_dev = NULL;
static ahci_hba_memory_regs_t *hba = NULL;

void probe_ports(int n_ports)
{
	uint32_t ports_impl = hba->ports_implemented;
	for(int i = 0; i < 32; i++)
	{
		if(ports_impl & 1)
		{
			if(hba->ports[i].sig)
				MPRINTF("Found a drive!\n");
		}
		ports_impl >>= 1;
		i++;
	}
}
int module_init()
{
	MPRINTF("initializing!\n");
	ahci_dev = get_pcidev_from_classes(CLASS_MASS_STORAGE_CONTROLLER, 6, 0);
	if(!ahci_dev)
	{
		MPRINTF("could not find a valid SATA device!\n");
		return 1;
	}

	pcibar_t *bar = pci_get_bar(ahci_dev->slot, ahci_dev->device, ahci_dev->function, 5);
	hba = (ahci_hba_memory_regs_t*)(((uintptr_t) bar->address) + PHYS_BASE);

	printf("Ports implemented: %u\n", count_bits(hba->ports_implemented));

	probe_ports(count_bits(hba->ports_implemented));
	return 0;
}
int module_fini()
{
	MPRINTF("de-initializing!\n");
	
	return 0;
}