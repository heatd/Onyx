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
#include <errno.h>

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
inline int ext2_add_singly_indirect_block(inode_t *inode, uint32_t block, uint32_t block_index, ext2_fs_t *fs)
{
	unsigned int min_singly_block = EXT2_DIRECT_BLOCK_COUNT;
	/* If the singly indirect bp doesn't exist, create it */
	if(!inode->single_indirect_bp)
		inode->single_indirect_bp = ext2_allocate_block(fs);
	uint32_t *buffer = malloc(fs->block_size);
	if(!buffer)
		return errno = ENOMEM, -1;
	memset(buffer, 0, fs->block_size);
	ext2_read_block_raw(inode->single_indirect_bp, 1, fs, buffer);
	buffer[block_index - min_singly_block] = block;
	ext2_write_block(inode->single_indirect_bp, 1, fs, buffer);
	free(buffer);
	return 0;
}
int ext2_add_block_to_inode(inode_t *inode, uint32_t block, uint32_t block_index, ext2_fs_t *fs)
{
	unsigned int type = ext2_detect_block_type(block, fs);
	switch(type)
	{
		case EXT2_TYPE_DIRECT_BLOCK:
		{
			inode->dbp[block_index] = block;
			break;
		}
		case EXT2_TYPE_SINGLY_BLOCK:
		{
			return ext2_add_singly_indirect_block(inode, block, block_index, fs);
		}
		/* TODO: Add doubly and triply block support */
		default:
		{
			printk("ext2: Double and trebly block support not implemented!");
			while(1);
		}
	}
	return 0;
}
void ext2_set_inode_size(inode_t *inode, size_t size)
{
	inode->size_hi = size >> 32;
	inode->size_lo = size & 0xFFFFFFFF;
}
