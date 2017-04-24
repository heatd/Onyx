/*----------------------------------------------------------------------
 * Copyright (C) 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdint.h>
#include <stdlib.h>
#include <kernel/compiler.h>

#include <drivers/ext2.h>
/* TODO: Add a way to prefer block groups */
uint32_t ext2_allocate_block(ext2_fs_t *fs)
{
	/* If we just don't have any blocks available, error */
	if(unlikely(fs->sb->unallocated_blocks == 0))
		return 0;
	for(uint32_t i = 0; i < fs->number_of_block_groups; i++)
	{
		if(fs->bgdt[i].unallocated_blocks_in_group == 0)
			continue;
		return ext2_allocate_from_block_group(fs, i);
	}
	return 0;
}
void ext2_free_block(uint32_t block, ext2_fs_t *fs)
{
	acquire_spinlock(&fs->sb_lock);
	fs->sb->unallocated_blocks++;
	release_spinlock(&fs->sb_lock);


}