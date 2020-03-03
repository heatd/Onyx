/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include <onyx/compiler.h>
#include <onyx/panic.h>

#include "ext2.h"

/* TODO: Add a way to prefer block groups */
/* Allocates a block */
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

/* Frees a block */
void ext2_free_block(uint32_t block, ext2_fs_t *fs)
{
	assert(block != EXT2_ERR_INV_BLOCK);

	spin_lock(&fs->sb_lock);
	
	fs->sb->unallocated_blocks++;

	uint32_t block_group = block / fs->blocks_per_block_group;
	
	assert(block_group <= fs->number_of_block_groups);

	ext2_free_block_bg(block, block_group, fs);
	
	spin_unlock(&fs->sb_lock);
}

/* Returns an struct ext2_inode from disk, and sets *inode_number to the inode number */
struct ext2_inode *ext2_allocate_inode(uint32_t *inode_number, ext2_fs_t *fs)
{
	/* If we just don't have any blocks available, error */
	if(unlikely(fs->sb->unallocated_inodes == 0))
		return 0;
	
	for(uint32_t i = 0; i < fs->number_of_block_groups; i++)
	{
		if(fs->bgdt[i].unallocated_inodes_in_group == 0)
			continue;
		return ext2_allocate_inode_from_block_group(inode_number, i, fs);
	}

	return 0;
}

void ext2_free_inode(uint32_t inode, ext2_fs_t *fs)
{
	uint32_t block_group = inode / fs->inodes_per_block_group;
	
	spin_lock(&fs->sb_lock);

	assert(block_group <= fs->number_of_block_groups);

	ext2_free_inode_bg(inode, block_group, fs);

	spin_unlock(&fs->sb_lock);
}
