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

#include <onyx/pagecache.h>

#include "ext2.h"

void ext2_set_inode_size(struct ext2_inode *inode, size_t size)
{
	inode->size_hi = size >> 32;
	inode->size_lo = size & 0xFFFFFFFF;
}

unsigned int ext2_detect_block_type(uint32_t block, struct ext2_superblock *fs)
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

/* Inspired by linux's ext2_block_to_path, essentially does something like it. */
unsigned int ext2_get_block_path(ext2_superblock *sb, ext2_block_no offsets[4], ext2_block_no block_nr)
{
	unsigned int type = ext2_detect_block_type(block_nr, sb);
	const unsigned int entries = (sb->block_size / sizeof(uint32_t));
	unsigned int min_singly_block = direct_block_count;
	unsigned int min_doubly_block = entries + direct_block_count;
	unsigned int min_trebly_block = entries * entries + entries + direct_block_count;
	unsigned int idx = 0;

	if(type == EXT2_TYPE_DIRECT_BLOCK)
		offsets[idx++] = block_nr;
	else if(type == EXT2_TYPE_SINGLY_BLOCK)
	{
		offsets[idx++] = EXT2_IND_BLOCK;
		offsets[idx++] = block_nr - min_singly_block;
	}
	else if(type == EXT2_TYPE_DOUBLY_BLOCK)
	{
		block_nr -= min_doubly_block;

		unsigned int doubly_table_index = block_nr >> sb->entry_shift;
		unsigned int singly_table_index = block_nr & (entries - 1);

		offsets[idx++] = EXT2_DIND_BLOCK;
		offsets[idx++] = doubly_table_index;
		offsets[idx++] = singly_table_index;
	}
	else if(type == EXT2_TYPE_TREBLY_BLOCK)
	{
		block_nr -= min_trebly_block;
		unsigned int trebly_table_index = block_nr >> (sb->entry_shift * 2);
		unsigned int doubly_table_index = (block_nr >> sb->entry_shift)
				& (entries - 1);
		unsigned int singly_table_index = block_nr & (entries - 1);

		offsets[idx++] = EXT2_TIND_BLOCK;
		offsets[idx++] = trebly_table_index;
		offsets[idx++] = doubly_table_index;
		offsets[idx++] = singly_table_index;
	}

	return idx;
}

expected<ext2_block_no, int> ext2_get_block_from_inode(ext2_inode *ino, ext2_block_no block, ext2_superblock *sb)
{
	ext2_block_no offsets[4];

	unsigned int len = ext2_get_block_path(sb, offsets, block);
	uint32_t *curr_block = ino->i_data;
	auto_block_buf buf;
	ext2_block_no dest_block_nr = 0;

	for(unsigned int i = 0; i < len; i++)
	{
		ext2_block_no off = offsets[i];

		/* We have to check if we're the last level, as to not read the dest block */
		if(i + 1 != len)
		{
			auto b = curr_block[off];

			if(b == EXT2_ERR_INV_BLOCK)
				return EXT2_ERR_INV_BLOCK;
			
			buf = sb_read_block(sb, b);
			if(!buf)
				return unexpected<int>{-errno};
			
			curr_block = static_cast<uint32_t *>(block_buf_data(buf));
		}
		else
		{
			dest_block_nr = curr_block[off];
		}
	}

	return dest_block_nr;
}

expected<ext2_block_no, int> ext2_create_path(struct inode *ino, ext2_block_no block, ext2_superblock *sb)
{
	auto preferred_bg = ext2_inode_number_to_bg(ino->i_inode, sb);
	auto raw_inode = ext2_get_inode_from_node(ino);

	ext2_block_no offsets[4];

	unsigned int len = ext2_get_block_path(sb, offsets, block);
	uint32_t *curr_block = raw_inode->i_data;
	auto_block_buf buf;
	ext2_block_no dest_block_nr = 0;

	for(unsigned int i = 0; i < len; i++)
	{
		ext2_block_no off = offsets[i];

		/* We have to check if we're the last level, as to not read the dest block */
		if(i + 1 != len && len != 1)
		{
			auto b = curr_block[off];

			bool should_zero_block = false;

			if(b == EXT2_ERR_INV_BLOCK)
			{
				auto block = sb->allocate_block(preferred_bg);
				if(block == EXT2_ERR_INV_BLOCK)
				{
					return unexpected<int>{-ENOSPC};
				}

				should_zero_block = true;

				b = curr_block[off] = block;

				if(buf) block_buf_dirty(buf);
				else
				{
					inode_update_ctime(ino);
					inode_mark_dirty(ino);
				}
			}
			
			buf = sb_read_block(sb, b);
			if(!buf)
				return unexpected<int>{-errno};
			
			curr_block = static_cast<uint32_t *>(block_buf_data(buf));
		
			if(should_zero_block) [[unlikely]]
			{
				memset(curr_block, 0, sb->block_size);
				block_buf_dirty(buf);
			}
		}
		else
		{
			dest_block_nr = curr_block[off];

			if(dest_block_nr == EXT2_FILE_HOLE_BLOCK)
			{
				auto block = sb->allocate_block();
				if(block == EXT2_ERR_INV_BLOCK)
					return unexpected<int>{-ENOSPC};
				
				dest_block_nr = curr_block[off] = block; 

				ino->i_blocks += sb->block_size / 512;
				inode_update_ctime(ino);
				inode_mark_dirty(ino);
			}
		}
	}

	return dest_block_nr;
}

int ext2_prepare_write(inode *ino, struct page *page, size_t page_off, size_t offset, size_t len)
{
	auto end = offset + len;
	auto sb = ext2_superblock_from_inode(ino);

	auto bufs = block_buf_from_page(page);

	auto base_block = page_off / sb->block_size;
	auto nr_blocks = PAGE_SIZE / sb->block_size;

	/* Handle pages that haven't been mapped yet */
	if(!bufs)
	{
		auto curr_off = 0;

		for(size_t i = 0; i < nr_blocks; i++)
		{
			struct block_buf *b = nullptr;
			if(!(b = page_add_blockbuf(page, curr_off)))
			{
				page_destroy_block_bufs(page);
				return -ENOMEM;
			}

			b->block_nr = EXT2_FILE_HOLE_BLOCK;
			b->block_size = sb->block_size;
			b->dev = sb->s_bdev;

			curr_off += PAGE_SIZE;
		}

		bufs = block_buf_from_page(page);
	}

	while(bufs)
	{
		if(bufs->page_off >= offset && bufs->page_off < end)
		{
			auto relative_block = bufs->page_off / sb->block_size;
	
			auto block_number = bufs->block_nr;

			if(block_number == EXT2_FILE_HOLE_BLOCK)
			{
				auto res = ext2_create_path(ino, base_block + relative_block, sb);

				if(res.has_error())
					return res.error();

				bufs->block_nr = res.value();
			}
		}

		bufs = bufs->next;
	}

	return 0;
}

int ext2_free_indirect_block(uint32_t block, unsigned int indirection_level, struct ext2_superblock *fs)
{
	auto buf = sb_read_block(fs, block);
	if(!buf)
	{
		fs->error("I/O error");
		return -EIO;
	}

	uint32_t *blockbuf = (uint32_t *) block_buf_data(buf);
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
			fs->free_block(blockbuf[i]);
		}
	}

out:
	free(blockbuf);
	return st;
}

void ext2_free_inode_space(struct ext2_inode *inode, struct ext2_superblock *fs)
{
	/* Free direct bps first */
	for(unsigned int i = 0; i < direct_block_count; i++)
	{
		uint32_t block = inode->i_data[i];

		if(block != 0)
		{
			/* Valid block, free */
			fs->free_block(block);
		}

		inode->i_data[i] = 0;
	}

	if(inode->i_data[EXT2_IND_BLOCK] != EXT2_FILE_HOLE_BLOCK)
	{
		ext2_free_indirect_block(inode->i_data[EXT2_IND_BLOCK], 1, fs);
		inode->i_data[EXT2_IND_BLOCK] = 0;
	}

	if(inode->i_data[EXT2_DIND_BLOCK] != EXT2_FILE_HOLE_BLOCK)
	{
		ext2_free_indirect_block(inode->i_data[EXT2_DIND_BLOCK], 2, fs);
		inode->i_data[EXT2_DIND_BLOCK] = 0;
	}

	if(inode->i_data[EXT2_TIND_BLOCK] != EXT2_ERR_INV_BLOCK)
	{
		ext2_free_indirect_block(inode->i_data[EXT2_TIND_BLOCK], 3, fs);
		inode->i_data[EXT2_TIND_BLOCK] = 0;
	}
}
