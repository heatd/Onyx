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
#include <mbr.h>
#include <partitions.h>
#include <stdio.h>
#include <stdlib.h>
#include <drivers/ext2.h>
int ext2_open_partition(uint64_t sector)
{
	printf("Handling ext2 partition at sector %d\n", sector);
	superblock_t *sb = vmm_allocate_virt_address(VM_KERNEL, 1/*64K*/, VMM_TYPE_REGULAR, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	vmm_map_range(sb, 1, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	uint32_t phys = (uint64_t)virtual2phys(sb) >> 0 & 0xFFFFFFFF;
	printf("phys: %x\n", phys);
	uint64_t lba = sector + 2;
	ata_read_sectors(0, 0, phys, 1024, lba);
	if(sb->ext2sig == 0xef53)
		printf("Valid ext2 signature detected!\n");
	else
		printf("ERROR: Invalid ext2 signature %x\n", sb->ext2sig);
	printf("Number of inodes: %d\nNumber of blocks: %d\n", sb->total_inodes,sb->total_blocks);
	printf("Size of struct: %d\n", sizeof(superblock_t));
	printf("Last mounted on %s\n", sb->ext.last_path);
	ext2_version_t version;
	version.major = sb->major_version;
	version.minor = sb->minor_version;
	printf("ext2 fs version %d.%d\n",version.major, version.minor);
	return 0;
}
void init_ext2drv()
{
	part_add_handler(EXT2_MBR_CODE, ext2_open_partition);
}
