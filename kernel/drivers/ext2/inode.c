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
#include <limits.h>
#include <stdio.h>
#include <drivers/ext2.h>

inode_t *ext2_allocate_inode_from_block_group(uint32_t *inode_no, uint32_t block_group, ext2_fs_t *fs)
{
	mutex_lock(&fs->ino_alloc_lock);
	block_group_desc_t *_block_group = &fs->bgdt[block_group];
	size_t total_size = fs->inodes_per_block_group / CHAR_BIT;
	size_t total_blocks = total_size % fs->block_size ? (total_size / fs->block_size) + 1 :
		total_size / fs->block_size;
	uint8_t *bitmap = ext2_read_block(_block_group->inode_usage_addr, total_blocks, fs);
	uint32_t inode = 0;
	if(!bitmap)
	{
		mutex_unlock(&fs->ino_alloc_lock);
		return 0;
	}
	for(uint32_t i = 0; i < total_size; i++)
	{
		if(bitmap[i] == 0xFF)
			continue;
		for(int j = 0; j < CHAR_BIT; j++)
		{
			if(!(bitmap[i] & (1 << j)))
			{
				/* Set the corresponding bit */
				bitmap[i] |= (1 << j);
				/* Change the block group and superblock structures in order to reflect it */
				_block_group->unallocated_inodes_in_group--;
				fs->sb->unallocated_inodes--;
				/* Actually register the changes on disk */
				/* We give the bitmap priority here, since there can be a disk failure or a shutdown at any time,
				   and this is the most important part */
				ext2_write_block(_block_group->inode_usage_addr, total_blocks, fs, bitmap);
				ext2_register_superblock_changes(fs);
				ext2_register_bgdt_changes(fs);
				mutex_unlock(&fs->ino_alloc_lock);
				inode = fs->inodes_per_block_group * block_group + i * CHAR_BIT + j;
				goto found;
			}
		}
	}
found:
	/* If we didn't find a free inode, return */
	if(inode == 0)
	{
		free(bitmap);
		return 0;
	}
	mutex_unlock(&fs->ino_alloc_lock);
	inode_t *ino = ext2_get_inode_from_number(fs, inode);
	/* TODO: Handle the inode leak here */
	if(!ino)
	{
		free(bitmap);
		return 0;
	}
	*inode_no = inode;
	free(bitmap);
	return ino;
}