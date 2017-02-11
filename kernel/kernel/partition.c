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
#include <partitions.h>
#include <stdio.h>
#include <errno.h>
#include <mbr.h>

#include <kernel/vmm.h>
static volatile fs_handler mbr_code_handlers[0xFF];

void partition_add_handler(enum partition_type_t type, uint8_t part_code, fs_handler handler)
{
	if(type == PARTITION_TYPE_MBR)
		mbr_code_handlers[part_code] = handler;
}
fs_handler lookup_handler_from_partition_code(enum partition_type_t type, uint8_t part_code)
{
	if(type == PARTITION_TYPE_MBR)
		return mbr_code_handlers[part_code];
	return NULL;
}
void partition_find_and_mount(enum partition_type_t type, int index, block_device_t *dev)
{
	/* Map the buffer */
	unsigned int *mbrbuf = malloc(512);
	if(!dev)
		return errno = ENOMEM, (void) 0;
	memset(mbrbuf, 0, 512);
	/* Read the mbr from the disk */
	blkdev_read(0, 512, mbrbuf, dev);
	mbrpart_t *part = (mbrpart_t*)((char *)mbrbuf + 0x1BE);
	printf("Partitions: \n");
	/* Cycle through all the partitions */
	for(int i = 0; i < 4; i++)
	{
		if(part->part_type != 0 && index == i)
		{
			printf("Partition %d: %d\nNumber of sectors: %d\nPartition type: 0%X\n" , i, part->sector, part->size_sector, part->part_type);
		 	fs_handler handler = lookup_handler_from_partition_code(PARTITION_TYPE_MBR, part->part_type);
			if(!handler) continue;
		 	
		 	handler(part->sector, dev);
			break;
		}
		part++;

	}
}