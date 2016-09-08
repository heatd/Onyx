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
#include <kernel/vmm.h>
#include <string.h>
#include <stdio.h>
#include <mbr.h>
#include <drivers/ata.h>
#include <partitions.h>
void read_partitions()
{
	/* Map the buffer */
	unsigned int *mbrbuf = vmm_allocate_virt_address(VM_KERNEL, 1 /*64K*/, VMM_TYPE_REGULAR, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	vmm_map_range(mbrbuf, 1, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	uint64_t phys = (uint64_t)virtual2phys(mbrbuf);
	uint32_t arg = (uint32_t)phys;
	asm volatile("sti");
	/* Read the mbr from the disk */
	ata_read_sectors(0, 0, arg, 512, 0);
	mbrpart_t *part = (mbrpart_t*)((char *)mbrbuf + 0x1BE);
	printf("Partitions: \n");
	/* Cycle through all the partitions */
	for(int i = 0; i < 4; i++)
	{
		if(part->part_type != 0)
		{
			printf("Partition %d: %d\nNumber of sectors: %d\nPartition type: 0%X\n" , i, part->sector, part->size_sector, part->part_type);
		 	fs_handler handler = lookup_handler_from_partition_code(part->part_type);
			 if(!handler) continue;
		 	handler(part->sector, 0, 0);
			 break;
		}
		part++;

	}

}
