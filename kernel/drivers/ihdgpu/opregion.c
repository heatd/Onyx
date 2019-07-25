/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include "igpu_drv.h"
#include "igd_opregion.h"
#include "vbt.h"

#include <errno.h>

#include <onyx/acpi.h>

#include <pci/pci.h>

int igd_get_opregion(struct igpu_device *dev)
{
	uint64_t opregion = pci_read(dev->device, ASLS, sizeof(uint32_t));

	if(opregion == OPREGION_NON_EXISTENT)
	{
		printk("igd: OpRegion not present in the system.\n");
		return -ENOENT;
	}

	void *opregion_map = mmiomap((void *) opregion, OPREGION_SIZE,
				     VM_WRITE | VM_NOEXEC);

	if(!opregion_map)
	{
		printk("igd: Error mapping OpRegion.\n");
		return -1;
	}

	dev->opregion = (volatile struct igd_opregion *) opregion_map;

	printk("OpRegion: %p\nOpregion Phys: %lx\n", dev->opregion, opregion);
	return 0;
}

int igd_validate_opregion(struct igpu_device *dev)
{
	if(memcmp((const void *) &dev->opregion->header.signature, OPREGION_SIGNATURE,
		 OPREGION_SIGNATURE_LEN))
	{
		printk("igd: Invalid OpRegion Signature %.16s\n",
		       dev->opregion->header.signature);
		return -1;
	}

	return 0;
}

int igd_parse_vbt(struct igpu_device *dev);

int igd_opregion_init(struct igpu_device *dev)
{
	if(igd_get_opregion(dev) < 0)
	{
		printk("IGD: Could not get OpRegion.\n");
		return -1;
	}

	if(igd_validate_opregion(dev) < 0)
	{
		printk("IGD: Invalid OpRegion.\n");
		return -1;
	}

	struct vbt_header *header = (void *) &dev->opregion->mailbox4;

	if(igd_is_valid_vbt(dev, header) < 0)
	{
		printk("igd: Invalid VBT.\n");
		return -1;
	}

	if(igd_parse_vbt(dev) < 0)
	{
		printk("igd_parse_vbt failed\n");
		return -1;
	}

	return 0;
}