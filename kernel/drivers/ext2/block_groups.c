/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h> //remove
#include <limits.h>

#include <kernel/compiler.h>

#include <drivers/ext2.h>
uint32_t ext2_allocate_from_block_group(ext2_fs_t *fs, uint32_t block_group)
{
	mutex_lock(&fs->bgdt_lock);
	block_group_desc_t *_block_group = &fs->bgdt[block_group];
	size_t total_size = fs->blocks_per_block_group / CHAR_BIT;
	size_t total_blocks = total_size % fs->block_size ? (total_size / fs->block_size) + 1 :
		total_size / fs->block_size;
	uint8_t *bitmap = ext2_read_block(_block_group->block_usage_addr, total_blocks, fs);
	if(!bitmap)
	{
		mutex_unlock(&fs->bgdt_lock);
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
				bitmap[i] |= (1 << j);
				_block_group->unallocated_blocks_in_group--;
				fs->sb->unallocated_blocks--;
				ext2_write_block(_block_group->block_usage_addr, total_blocks, fs, bitmap);
				ext2_register_superblock_changes(fs);
				ext2_register_bgdt_changes(fs);
				mutex_unlock(&fs->bgdt_lock);
				return fs->blocks_per_block_group * block_group + i * CHAR_BIT + j;
			}
		}
	}
	mutex_unlock(&fs->bgdt_lock);
	return 0;
}
