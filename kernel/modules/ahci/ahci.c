/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
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
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_INSERT_VERSION();

#define MPRINTF(...) printf("ahci: "__VA_ARGS__)

static PCIDevice *ahci_dev = NULL;
static ahci_hba_memory_regs_t *hba = NULL;

int ahci_check_drive_type(ahci_port_t *port)
{
	uint32_t status = port->sata_status;

	uint8_t ipm = (status >> 8) & 0x0F;
	uint8_t det = status & 0x0F;

	if(!det)
		return -1;
	if(!ipm)
		return -1;
	
	if(!port->sig)
		return -1;
	return port->sig;
}
void ahci_probe_ports(int n_ports)
{
	uint32_t ports_impl = hba->ports_implemented;
	for(int i = 0; i < 32; i++)
	{
		if(ports_impl & 1)
		{
			int type = 0;
			if((type = ahci_check_drive_type(&hba->ports[i])))
			{
				switch(type)
				{
					case SATA_SIG_ATA:
						MPRINTF("Found a SATA drive on port %u\n", i);
						break;
					case SATA_SIG_ATAPI:
						MPRINTF("Found a SATAPI drive on port %u\n", i);
						break;
				}
			}
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

	MPRINTF("ports implemented: %u\n", count_bits32(hba->ports_implemented));

	ahci_probe_ports(count_bits32(hba->ports_implemented));
	return 0;
}
int module_fini()
{
	MPRINTF("de-initializing!\n");
	return 0;
}