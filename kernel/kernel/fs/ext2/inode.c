/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "ext2.h"

/* This is the max reserved inode number, everything below it is reserved */
#define EXT2_UNDEL_DIR_INO		6

struct ext2_inode *ext2_allocate_inode_from_block_group(uint32_t *inode_no,
	uint32_t block_group, ext2_fs_t *fs)
{
	/* TODO: Optimize this a-la block_groups.c */
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
		return NULL;
	}

	for(uint32_t i = 0; i < total_size; i++)
	{
		if(bitmap[i] == 0xFF)
			continue;
		for(int j = 0; j < CHAR_BIT; j++)
		{
			uint32_t this_inode = fs->inodes_per_block_group * block_group
					+ i * CHAR_BIT + j + 1;
	
			if(this_inode <= EXT2_UNDEL_DIR_INO)
				continue;
			if((bitmap[i] & (1 << j)) == 0)
			{
				/* Set the corresponding bit */
				bitmap[i] |= (1 << j);
				/* Change the block group and superblock
				 structures in order to reflect it */
				_block_group->unallocated_inodes_in_group--;
				fs->sb->unallocated_inodes--;
				/* Actually register the changes on disk */
				/* We give the bitmap priority here,
				 * since there can be a disk failure or a
				 * shutdown at any time,
				 * and this is the most important part */
				ext2_write_block(_block_group->inode_usage_addr,
						 total_blocks, fs, bitmap);
				ext2_register_superblock_changes(fs);
				ext2_register_bgdt_changes(fs);
				inode = this_inode;
				mutex_unlock(&fs->ino_alloc_lock);
				goto found;
			}
		}
	}
found:
	/* If we didn't find a free inode, return */
	if(inode == 0)
	{
		free(bitmap);
		return NULL;
	}

	struct ext2_inode *ino = ext2_get_inode_from_number(fs, inode);

	/* TODO: Handle the inode leak here */
	if(!ino)
	{
		free(bitmap);
		return NULL;
	}

	*inode_no = inode;
	free(bitmap);

	return ino;
}

int ext2_free_inode_bg(uint32_t inode, uint32_t block_group, ext2_fs_t *fs)
{
	/* TODO: Same as above */
	mutex_lock(&fs->ino_alloc_lock);
	block_group_desc_t *_block_group = &fs->bgdt[block_group];
	size_t total_size = fs->inodes_per_block_group / CHAR_BIT;
	size_t total_blocks = total_size % fs->block_size ? (total_size / fs->block_size) + 1 :
		total_size / fs->block_size;

	uint8_t *bitmap = ext2_read_block(_block_group->inode_usage_addr, total_blocks, fs);

	if(!bitmap)
	{
		mutex_unlock(&fs->ino_alloc_lock);
		return 0;
	}

	inode -= 1;
	uint32_t byte_off = (inode - (fs->inodes_per_block_group * block_group)) / CHAR_BIT;

	uint32_t bit_off = (inode - (fs->inodes_per_block_group * block_group)) - byte_off * CHAR_BIT;

	bitmap[byte_off] &= ~(1 << bit_off);

	ext2_write_block(_block_group->inode_usage_addr, total_blocks, fs, bitmap);

	free(bitmap);

	mutex_unlock(&fs->ino_alloc_lock);
	return 0;
}

int ext2_add_singly_indirect_block(struct ext2_inode *inode, uint32_t block,
	uint32_t block_index, ext2_fs_t *fs)
{
	bool allocated_single = false;

	unsigned int min_singly_block = EXT2_DIRECT_BLOCK_COUNT;
	/* If the singly indirect bp doesn't exist, create it */
	if(!inode->single_indirect_bp)
	{
		inode->single_indirect_bp = ext2_allocate_block(fs);
		allocated_single = true;

		if(inode->single_indirect_bp == EXT2_ERR_INV_BLOCK)
		{
			inode->single_indirect_bp = 0;
			return -1;
		}
		/* Overwrite the block */
		ext2_write_block(inode->single_indirect_bp, 1, fs, fs->zero_block);
	}

	uint32_t *buffer = malloc(fs->block_size);
	if(!buffer)
	{
		if(allocated_single)
		{
			ext2_free_block(inode->single_indirect_bp, fs);
			inode->single_indirect_bp = 0;
		}
		return -1;
	}

	ext2_read_block_raw(inode->single_indirect_bp, 1, fs, buffer);
	buffer[block_index - min_singly_block] = block;
	ext2_write_block(inode->single_indirect_bp, 1, fs, buffer);

	inode->i_blocks += fs->block_size / 512;

	free(buffer);

	return 0;
}

int ext2_add_doubly_indirect_block(struct ext2_inode *inode, uint32_t block,
	uint32_t block_index, ext2_fs_t *fs)
{
	const unsigned int entries = (fs->block_size / sizeof(uint32_t));
	unsigned int min_doubly_block = entries + direct_block_count;
	block_index -= min_doubly_block;
	unsigned int doubly_table_index = block_index >> fs->entry_shift;
	unsigned int singly_table_index = block_index & (entries - 1);

	
	uint32_t *buf = zalloc(fs->block_size);
	if(!buf)
		return -1;

	uint32_t dp;

	/* We use these bools do know if we need to free a block */
	bool allocated_doubly = false;

	if((dp = inode->doubly_indirect_bp) != 0)
		ext2_read_block_raw(inode->doubly_indirect_bp, 1, fs, buf);
	else
	{
		dp = ext2_allocate_block(fs);
		allocated_doubly = true;

		if(dp == EXT2_ERR_INV_BLOCK)
		{
			free(buf);
			return -1;
		}

		inode->doubly_indirect_bp = dp;
		ext2_write_block(inode->doubly_indirect_bp, 1, fs, fs->zero_block);
	}

	uint32_t singly_bp = buf[doubly_table_index];

	if(!singly_bp)
	{
		singly_bp = ext2_allocate_block(fs);

		if(singly_bp == EXT2_ERR_INV_BLOCK)
		{
			if(allocated_doubly)
			{
				ext2_free_block(dp, fs);
				inode->doubly_indirect_bp = 0;
			}

			free(buf);
			return -1;
		}

		buf[doubly_table_index] = singly_bp;
		ext2_write_block(dp, 1, fs, buf);
		memset(buf, 0, fs->block_size);
	}
	else
		ext2_read_block_raw(singly_bp, 1, fs, buf);

	
	buf[singly_table_index] = block;

	/* Always flush the singly indirect block */
	ext2_write_block(singly_bp, 1, fs, buf);

	inode->i_blocks += fs->block_size / 512;

	free(buf);

	return 0;
}

int ext2_add_trebly_indirect_block(struct ext2_inode *inode, uint32_t block,
	uint32_t block_index, ext2_fs_t *fs)
{
	const unsigned int entries = (fs->block_size / sizeof(uint32_t));
	unsigned int min_trebly_block = entries * entries + entries + direct_block_count;

	block_index -= min_trebly_block;

	unsigned int trebly_table_index = block_index >> (fs->entry_shift * 2);
	unsigned int doubly_table_index = (block_index >> fs->entry_shift)
			                  & (entries - 1);
	unsigned int singly_table_index = block_index & (entries - 1);
	bool allocated_trebly = false;
	bool allocated_doubly = false;

	uint32_t *buf = malloc(fs->block_size);

	uint32_t tbp;
	uint32_t dbp;
	uint32_t sbp;

	if(!(tbp = inode->trebly_indirect_bp))
	{
		uint32_t n = tbp = ext2_allocate_block(fs);
		if(n == EXT2_ERR_INV_BLOCK)
		{
			free(buf);
			return -1;
		}

		allocated_trebly = true;

		inode->trebly_indirect_bp = n;
		memset(buf, 0, fs->block_size);
		ext2_write_block(n, 1, fs, fs->zero_block);
	}
	else
		ext2_read_block_raw(inode->trebly_indirect_bp, 1, fs, buf);
	
	if(!(dbp = buf[trebly_table_index]))
	{
		uint32_t n = dbp = ext2_allocate_block(fs);

		if(n == EXT2_ERR_INV_BLOCK)
		{
			if(allocated_trebly)
			{
				ext2_free_block(tbp, fs);
				inode->trebly_indirect_bp = 0;
			}

			free(buf);
			return -1;
		}

		buf[trebly_table_index] = n;
		ext2_write_block(n, 1, fs, fs->zero_block);
		ext2_write_block(tbp, 1, fs, buf);
		memset(buf, 0, fs->block_size);
	}
	else
		ext2_read_block_raw(dbp, 1, fs, buf);
	
	if(!(sbp = buf[doubly_table_index]))
	{
		uint32_t n = sbp = ext2_allocate_block(fs);

		if(n == EXT2_ERR_INV_BLOCK)
		{
			(void) allocated_doubly;
			/* TODO: Do this error path */
			free(buf);
			return -1;
		}

		buf[doubly_table_index] = n;
		ext2_write_block(dbp, 1, fs, buf);
		memset(buf, 0, fs->block_size);
	}
	else
		ext2_read_block_raw(sbp, 1, fs, buf);

	buf[singly_table_index] = block;
	ext2_write_block(sbp, 1, fs, buf);

	inode->i_blocks += fs->block_size / 512;

	free(buf);

	return 0;
}

int ext2_add_block_to_inode(struct ext2_inode *inode, uint32_t block, uint32_t block_index, ext2_fs_t *fs)
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
			return ext2_add_singly_indirect_block(inode, block, block_index, fs);
		}
		case EXT2_TYPE_DOUBLY_BLOCK:
		{
			return ext2_add_doubly_indirect_block(inode, block, block_index, fs);
		}
		case EXT2_TYPE_TREBLY_BLOCK:
		{
			return ext2_add_trebly_indirect_block(inode, block, block_index, fs);
		}
	}

	return errno = ENOSPC, EXT2_ERR_INV_BLOCK;
}

void ext2_set_inode_size(struct ext2_inode *inode, size_t size)
{
	inode->size_hi = size >> 32;
	inode->size_lo = size & 0xFFFFFFFF;
}

unsigned int ext2_detect_block_type(uint32_t block, ext2_fs_t *fs)
{
	const unsigned int entries = (fs->block_size / sizeof(uint32_t));
	unsigned int min_singly_block = direct_block_count;
	unsigned int min_doubly_block = entries + direct_block_count;
	unsigned int min_trebly_block = entries * entries + entries + direct_block_count;

	if(block < min_singly_block)
		return EXT2_TYPE_DIRECT_BLOCK;
	else if(block >= min_singly_block && block < min_doubly_block)
		return EXT2_TYPE_SINGLY_BLOCK;
	else if(block >= min_doubly_block && block < min_trebly_block)
		return EXT2_TYPE_DOUBLY_BLOCK;
	return EXT2_TYPE_TREBLY_BLOCK;
}

uint32_t ext2_get_block_from_inode(struct ext2_inode *ino, uint32_t block, ext2_fs_t *fs);

ssize_t ext2_read_inode_block(struct ext2_inode *ino, uint32_t blk, char *buffer, ext2_fs_t *fs)
{
	uint32_t fs_block = ext2_get_block_from_inode(ino, blk, fs);
	if(fs_block == EXT2_ERR_INV_BLOCK)
		return 0;

	ext2_read_block_raw(fs_block, 1, fs, buffer);
	return fs->block_size;
}

uint32_t ext2_get_block_from_inode(struct ext2_inode *ino, uint32_t block, ext2_fs_t *fs)
{
	unsigned int type = ext2_detect_block_type(block, fs);

	const unsigned int entries = (fs->block_size / sizeof(uint32_t));
	unsigned int min_singly_block = direct_block_count;
	unsigned int min_doubly_block = entries + direct_block_count;
	unsigned int min_trebly_block = entries * entries + entries + direct_block_count;

	uint32_t ret = 0;
	/* TODO: Ensure all this code handles file holes correctly */
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
				return EXT2_ERR_INV_BLOCK;

			if(!ino->single_indirect_bp)
			{
				ret = 0;
				free(scratch);
				break;
			}

			ext2_read_block_raw(ino->single_indirect_bp, 1, fs, scratch);
			ret = scratch[block - min_singly_block];

			free(scratch);
			break;
		}
	
		case EXT2_TYPE_DOUBLY_BLOCK:
		{
			uint32_t *scratch = malloc(fs->block_size);
			if(!scratch)
				return EXT2_ERR_INV_BLOCK;

			uint32_t block_index = block;
			if(!ino->doubly_indirect_bp)
			{
				ret = 0;
				free(scratch);
				break;
			}

			block_index -= min_doubly_block;

			unsigned int doubly_table_index = block_index >> fs->entry_shift;
			unsigned int singly_table_index = block_index & (entries - 1);
			
			ext2_read_block_raw(ino->doubly_indirect_bp, 1, fs, scratch);

			if(!scratch[doubly_table_index])
			{
				ret = 0;
				free(scratch);
				break;
			}

			ext2_read_block_raw(scratch[doubly_table_index], 1, fs, scratch);

			ret = scratch[singly_table_index];
			free(scratch);
			break;
		}
	
		case EXT2_TYPE_TREBLY_BLOCK:
		{
			uint32_t *scratch = malloc(fs->block_size);
			if(!scratch)
				return EXT2_ERR_INV_BLOCK;
			if(!ino->trebly_indirect_bp)
			{
				free(scratch);
				ret = 0;
				break;
			}

			uint32_t block_index = block;
			block_index -= min_trebly_block;

			unsigned int trebly_table_index = block_index >> (fs->entry_shift * 2);
			unsigned int doubly_table_index = (block_index >> fs->entry_shift)
				& (entries - 1);
			unsigned int singly_table_index = block_index & (entries - 1);


			ext2_read_block_raw(ino->trebly_indirect_bp, 1, fs, scratch);

			uint32_t dbp = scratch[trebly_table_index];
			
			if(!dbp)
			{
				free(scratch);
				ret = 0;
				break;
			}

			ext2_read_block_raw(dbp, 1, fs, scratch);

			uint32_t sbp = scratch[doubly_table_index];

			if(!sbp)
			{
				free(scratch);
				ret = 0;
				break;
			}

			ext2_read_block_raw(sbp, 1, fs, scratch);

			ret = scratch[singly_table_index];
			free(scratch);
			break;
		}
	}

	if(ret == 0)
		ret = EXT2_ERR_INV_BLOCK;
	return ret;
}

uint32_t ext2_get_inode_block(struct ext2_inode *ino, uint32_t block, ext2_fs_t *fs)
{
	uint32_t b = ext2_get_block_from_inode(ino, block, fs);
	if(b == EXT2_ERR_INV_BLOCK)
	{
		/* We'll have to allocate a new block and add it in */
		uint32_t new_block = ext2_allocate_block(fs);
		ext2_add_block_to_inode(ino, new_block, block, fs);

		return new_block;
	}
	else
		return b;
}

ssize_t ext2_write_inode_block(struct ext2_inode *ino, uint32_t block, char *buffer, ext2_fs_t *fs)
{
	uint32_t blk = ext2_get_inode_block(ino, block, fs);
	if(blk == EXT2_ERR_INV_BLOCK)
		return -1;
	ext2_write_block(blk, 1, fs, buffer);

	return fs->block_size;
}

/* TODO: Don't assume ext2_read_inode_block and ext2_write_inode_block don't fail. */
ssize_t ext2_write_inode(struct ext2_inode *ino, ext2_fs_t *fs, size_t size, off_t off, char *buffer)
{
	char *scratch = zalloc(fs->block_size);
	if(!scratch)
		return errno = ENOMEM, -1;

	ssize_t written = 0;
	while(written != (ssize_t) size)
	{
		uint32_t block = off / fs->block_size;
		off_t block_off = off % fs->block_size;
		off_t block_left = fs->block_size - block_off;
		
		ext2_read_inode_block(ino, block, scratch, fs);

		size_t amount = (ssize_t) size - written < block_left ?
			(ssize_t) size - written : block_left;
		
		memcpy(scratch + block_off, buffer + written, amount);
		/* < 0)
		{
			free(scratch);
			return errno = EFAULT, -1;
		}*/
		
		assert(ext2_write_inode_block(ino, block, scratch, fs) != -1);
		
		written += amount;
		off += amount;
	}

	free(scratch);
	return written;
}

/* Reads off an inode */
ssize_t ext2_read_inode(struct ext2_inode *ino, ext2_fs_t *fs, size_t size, off_t off, char *buffer)
{
	/* This scratch buffer is too big to be allocated on the stack */
	char *scratch = malloc(fs->block_size);
	if(!scratch)
		return errno = ENOMEM, -1;
	ssize_t read = 0;

	while(read != (ssize_t) size)
	{
		uint32_t block = off / fs->block_size;
		off_t block_off = off % fs->block_size;
		off_t block_left = fs->block_size - block_off;

		ext2_read_inode_block(ino, block, scratch, fs);
		size_t amount = (ssize_t) (size - read) < block_left ? (ssize_t) size - read : block_left;
		
		memcpy(buffer + read, scratch + block_off, amount);
		/* < 0)
		{
			free(scratch);
			return errno = EFAULT, -1;
		}*/

		read += amount;
		off += amount;
	}

	free(scratch);
	return read;
}

int ext2_free_indirect_block(uint32_t block, unsigned int indirection_level, ext2_fs_t *fs)
{
	uint32_t *blockbuf = ext2_read_block(block, 1, fs);
	if(!blockbuf)
		return -1;

	int st = 0;
	
	unsigned int nr_entries = fs->block_size / sizeof(uint32_t);

	for(unsigned int i = 0; i < nr_entries; i++)
	{
		if(blockbuf[i] == EXT2_ERR_INV_BLOCK)
			continue;

		if(indirection_level != 1)
		{
			st = ext2_free_indirect_block(blockbuf[i], indirection_level - 1, fs);

			if(st < 0)
			{
				goto out;
			}
		}
		else
		{
			ext2_free_block(blockbuf[i], fs);
		}
	}

out:
	free(blockbuf);
	return st;
}

void ext2_free_inode_space(struct ext2_inode *inode, ext2_fs_t *fs)
{
	/* Free direct bps first */
	for(unsigned int i = 0; i < direct_block_count; i++)
	{
		uint32_t block = inode->dbp[i];

		if(block != 0)
		{
			/* Valid block, free */
			ext2_free_block(block, fs);
		}

		inode->dbp[i] = 0;
	}

	if(inode->single_indirect_bp != EXT2_ERR_INV_BLOCK)
	{
		ext2_free_indirect_block(inode->single_indirect_bp, 1, fs);
	}

	if(inode->doubly_indirect_bp != EXT2_ERR_INV_BLOCK)
	{
		ext2_free_indirect_block(inode->doubly_indirect_bp, 2, fs);
	}

	if(inode->trebly_indirect_bp != EXT2_ERR_INV_BLOCK)
	{
		ext2_free_indirect_block(inode->trebly_indirect_bp, 3, fs);
	}
}
