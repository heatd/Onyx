/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h> //remove
#include <limits.h>

#include <onyx/compiler.h>

#include "ext2.h"

uint32_t ext2_get_block_bitmap_size(ext2_fs_t *fs)
{
	return fs->blocks_per_block_group / CHAR_BIT;
}

uint32_t ext2_bitmap_size_to_nr_blocks(uint32_t size, ext2_fs_t *fs)
{
	return size % fs->block_size ? (size / fs->block_size) + 1 :
           size / fs->block_size;
}

uint8_t *ext2_get_block_bitmap(block_group_desc_t *_block_group, uint32_t block_index, ext2_fs_t *fs)
{
	size_t total_size = ext2_get_block_bitmap_size(fs);
	size_t total_blocks = ext2_bitmap_size_to_nr_blocks(total_size, fs) - block_index;

	uint8_t *bitmap = ext2_read_block(_block_group->block_usage_addr + block_index, total_blocks, fs);
	
	return bitmap;
}

void ext2_flush_block_bitmap(uint8_t *bitmap_base, uint8_t *bit_location,
                             block_group_desc_t *desc, ext2_fs_t *fs)
{
	uint32_t base_bitmap_block = desc->block_usage_addr;

	/* Get the offset from the base of the bitmap, and then align it to a block boundary */
	
	size_t byte_off = bit_location - bitmap_base;

	/* This math is valid because block_size is always a power of 2 */
	byte_off &= ~(fs->block_size - 1);

	uint32_t block_idx = byte_off / fs->block_size;

	ext2_write_block(base_bitmap_block + block_idx, 1, fs, bitmap_base + byte_off);
}

uint32_t ext2_allocate_from_block_group(ext2_fs_t *fs, uint32_t block_group)
{
	mutex_lock(&fs->bgdt_lock);
	block_group_desc_t *_block_group = &fs->bgdt[block_group];
	
	uint8_t *bitmap = ext2_get_block_bitmap(_block_group, 0, fs);
	if(!bitmap)
	{
		mutex_unlock(&fs->bgdt_lock);
		return EXT2_ERR_INV_BLOCK;
	}

	uint32_t bitmap_size = ext2_get_block_bitmap_size(fs);

	for(uint32_t i = 0; i < bitmap_size; i++)
	{
		if(bitmap[i] == 0xff)
			continue;
		for(int j = 0; j < CHAR_BIT; j++)
		{
			if(!(bitmap[i] & (1 << j)))
			{
				bitmap[i] |= (1 << j);
				_block_group->unallocated_blocks_in_group--;
				fs->sb->unallocated_blocks--;
				ext2_flush_block_bitmap(bitmap, &bitmap[i], _block_group, fs);
				ext2_register_superblock_changes(fs);
				ext2_register_bgdt_changes(fs);
				mutex_unlock(&fs->bgdt_lock);
				free(bitmap);
				return fs->blocks_per_block_group * block_group + i * CHAR_BIT + j;
			}
		}
	}

	free(bitmap);

	mutex_unlock(&fs->bgdt_lock);
	return 0;
}

int ext2_free_block_bg(uint32_t block, uint32_t block_group, ext2_fs_t *fs)
{
	mutex_lock(&fs->bgdt_lock);

	uint32_t base_block = fs->blocks_per_block_group * block_group;
	uint32_t bit_idx = base_block - block;
	uint32_t byte_idx = bit_idx / CHAR_BIT;
	uint32_t block_aligned_off = byte_idx & ~(fs->block_size - 1);

	block_group_desc_t *bg = &fs->bgdt[block_group];

	/* Calculate the block we need to access */
	uint32_t block_bitmap_index = block_aligned_off / fs->block_size;

	uint8_t *bitmap = ext2_get_block_bitmap(bg, block_bitmap_index, fs);
	if(!bitmap)
	{
		mutex_unlock(&fs->bgdt_lock);
		return -1;
	}

	bit_idx -= byte_idx * CHAR_BIT;

	bitmap[byte_idx - block_aligned_off] &= ~(1 << bit_idx);

	ext2_flush_block_bitmap(bitmap, &bitmap[byte_idx - block_aligned_off], bg, fs);

	mutex_unlock(&fs->bgdt_lock);

	return 0;
}
