/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
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
	{
		inode->single_indirect_bp = ext2_allocate_block(fs);
		/* Overwrite the block */
		ext2_write_block(inode->single_indirect_bp, 1, fs, fs->zero_block);
	}
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
	unsigned int type = ext2_detect_block_type(block_index, fs);
	switch(type)
	{
		case EXT2_TYPE_DIRECT_BLOCK:
		{
			inode->dbp[block_index] = block;
			inode->i_blocks += fs->block_size / 512;
			break;
		}
		case EXT2_TYPE_SINGLY_BLOCK:
		{
			inode->i_blocks += fs->block_size / 512;
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
unsigned int ext2_detect_block_type(uint32_t block, ext2_fs_t *fs)
{
	unsigned int min_singly_block = direct_block_count;
	unsigned int min_doubly_block = (fs->block_size / sizeof(uint32_t)) * (fs->block_size / sizeof(uint32_t));
	unsigned int min_trebly_block = min_doubly_block * (fs->block_size / sizeof(uint32_t));

	if(block < min_singly_block)
		return EXT2_TYPE_DIRECT_BLOCK;
	else if(block >= min_singly_block && block < min_doubly_block)
		return EXT2_TYPE_SINGLY_BLOCK;
	else if(block >= min_doubly_block && block < min_trebly_block)
		return EXT2_TYPE_DOUBLY_BLOCK;
	return EXT2_TYPE_TREBLY_BLOCK;
}
ssize_t ext2_read_inode_block(inode_t *ino, uint32_t blk, char *buffer, ext2_fs_t *fs)
{
	unsigned int type = ext2_detect_block_type(blk, fs);

	unsigned int min_singly_block = direct_block_count;
	unsigned int min_doubly_block = (fs->block_size / sizeof(uint32_t)) * (fs->block_size / sizeof(uint32_t));
	unsigned int min_trebly_block = min_doubly_block * (fs->block_size / sizeof(uint32_t));

	switch(type)
	{
		case EXT2_TYPE_DIRECT_BLOCK:
		{
			ext2_read_block_raw(ino->dbp[blk], 1, fs, buffer);
			break;
		}
		case EXT2_TYPE_SINGLY_BLOCK:
		{
			uint32_t *sbp = malloc(fs->block_size);
			if(!sbp)
				return errno = ENOMEM, -1;
			ext2_read_block_raw(ino->single_indirect_bp, 1, fs, sbp);
			ext2_read_block_raw(sbp[blk - min_singly_block], 1, fs, buffer);
			free(sbp);
			break;
		}
		case EXT2_TYPE_DOUBLY_BLOCK:
		{
			uint32_t *block = malloc(fs->block_size);
			if(!block)
				return errno = ENOMEM, -1;
			uint32_t block_index = blk;
			ext2_read_block_raw(ino->doubly_indirect_bp, 1, fs, block);
			ext2_read_block_raw(block[block_index - min_doubly_block], 1, fs, block);
			block_index -= min_doubly_block;
			ext2_read_block_raw(block[block_index - min_singly_block], 1, fs, buffer);

			free(block);
			break;
		}
		case EXT2_TYPE_TREBLY_BLOCK:
		{
			uint32_t *block = malloc(fs->block_size);
			if(!block)
				return errno = ENOMEM, -1;
			uint32_t block_index = blk - min_trebly_block;
			ext2_read_block_raw(ino->trebly_indirect_bp, 1, fs, block);
			ext2_read_block_raw(block[block_index], 1, fs, block);
			block_index -= min_doubly_block;
			ext2_read_block_raw(block[block_index], 1, fs, block);
			block_index -= min_doubly_block;
			ext2_read_block_raw(block[block_index - min_singly_block], 1, fs, buffer);

			free(block);
			break;
		}
	}
	return fs->block_size;
}
ssize_t ext2_get_block_from_inode(inode_t *ino, uint32_t block, ext2_fs_t *fs)
{
	unsigned int type = ext2_detect_block_type(block, fs);

	unsigned int min_singly_block = direct_block_count;
	unsigned int min_doubly_block = (fs->block_size / sizeof(uint32_t)) * (fs->block_size / sizeof(uint32_t));
	unsigned int min_trebly_block = min_doubly_block * (fs->block_size / sizeof(uint32_t));

	uint32_t ret = 0;
	switch(type)
	{
		case EXT2_TYPE_DIRECT_BLOCK:
		{
			ret = ino->dbp[block];
			break;
		}
		case EXT2_TYPE_SINGLY_BLOCK:
		{
			uint32_t *scratch = malloc(fs->block_size);
			if(!scratch)
				return errno = ENOMEM, -1;
			ext2_read_block_raw(ino->single_indirect_bp, 1, fs, scratch);
			ret = scratch[block - min_singly_block];
			free(scratch);
			break;
		}
		case EXT2_TYPE_DOUBLY_BLOCK:
		{
			uint32_t *scratch = malloc(fs->block_size);
			if(!scratch)
				return errno = ENOMEM, -1;
			uint32_t block_index = block;
			ext2_read_block_raw(ino->doubly_indirect_bp, 1, fs, scratch);
			ext2_read_block_raw(scratch[block_index - min_doubly_block], 1, fs, scratch);
			block_index -= min_doubly_block;
			ret = scratch[block_index - min_singly_block];
			free(scratch);
			break;
		}
		case EXT2_TYPE_TREBLY_BLOCK:
		{
			uint32_t *scratch = malloc(fs->block_size);
			if(!scratch)
				return errno = ENOMEM, -1;
			uint32_t block_index = block - min_trebly_block;
			ext2_read_block_raw(ino->trebly_indirect_bp, 1, fs, scratch);
			ext2_read_block_raw(scratch[block_index], 1, fs, scratch);
			block_index -= min_doubly_block;
			ext2_read_block_raw(scratch[block_index], 1, fs, scratch);
			block_index -= min_doubly_block;
			ret = scratch[block_index - min_singly_block];
			free(scratch);
			break;
		}
	}
	return ret;
}
uint32_t ext2_get_inode_block(inode_t *ino, uint32_t block, ext2_fs_t *fs)
{
	size_t total_size = EXT2_CALCULATE_SIZE64(ino);
	uint32_t max_blocks = total_size % fs->block_size ? (total_size / fs->block_size) + 1 : total_size / fs->block_size;
	if(max_blocks < block)
	{
		/* We'll have to allocate a new block and add it in */
		uint32_t new_block = ext2_allocate_block(fs);
		ext2_add_block_to_inode(ino, new_block, block, fs);
		return new_block;
	}
	else
		return ext2_get_block_from_inode(ino, block, fs);
	return -1;
}
ssize_t ext2_write_inode_block(inode_t *ino, uint32_t block, char *buffer, ext2_fs_t *fs)
{
	uint32_t blk = ext2_get_inode_block(ino, block, fs);
	if((int32_t) blk < 0)
		return -1;
	ext2_write_block(blk, 1, fs, buffer);
	return fs->block_size;
}
ssize_t ext2_write_inode(inode_t *ino, ext2_fs_t *fs, size_t size, off_t off, char *buffer)
{
	char *scratch = malloc(fs->block_size);
	if(!scratch)
		return errno = ENOMEM, -1;
	memset(scratch, 0, fs->block_size);
	ssize_t written = 0;
	while(written != (ssize_t) size)
	{
		uint32_t block = off / fs->block_size;
		off_t block_off = off % fs->block_size;
		off_t block_left = fs->block_size - block_off;
		ext2_read_inode_block(ino, block, scratch, fs);
		size_t amount = (ssize_t) size - written < block_left ? (ssize_t) size - written : block_left;
		memcpy(scratch + block_off, buffer + written, amount);
		ext2_write_inode_block(ino, block, scratch, fs);
		written += amount;
		off += amount;
	}
	free(scratch);
	return written;
}
/* Reads off an inode */
ssize_t ext2_read_inode(inode_t *ino, ext2_fs_t *fs, size_t size, off_t off, char *buffer)
{
	/* This scratch buffer is too big to be allocated on the stack */
	char *scratch = malloc(fs->block_size);
	if(!scratch)
		return errno = ENOMEM, -1;
	memset(scratch, 0, fs->block_size);
	ssize_t read = 0;
	while(read != (ssize_t) size)
	{
		uint32_t block = off / fs->block_size;
		off_t block_off = off % fs->block_size;
		off_t block_left = fs->block_size - block_off;
		ext2_read_inode_block(ino, block, scratch, fs);
		size_t amount = (ssize_t) (size - read) < block_left ? (ssize_t) size - read : block_left;
		memcpy(buffer + read, scratch + block_off, amount);
		read += amount;
		off += amount;
	}
	free(scratch);
	return read;
}
