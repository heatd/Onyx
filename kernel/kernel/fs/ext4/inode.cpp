/*
 * Copyright (c) 2017 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <onyx/limits.h>
#include <onyx/log.h>
#include <onyx/pagecache.h>

#include "ext4.h"

#include <onyx/utility.hpp>

void ext4_set_inode_size(struct ext4_inode *inode, size_t size)
{
    inode->i_size_hi = size >> 32;
    inode->i_size_lo = size & 0xFFFFFFFF;
}

unsigned int ext4_detect_block_type(uint32_t block, struct ext4_superblock *fs)
{
    const unsigned int entries = (fs->block_size / sizeof(uint32_t));
    unsigned int min_singly_block = direct_block_count;
    unsigned int min_doubly_block = entries + direct_block_count;
    unsigned int min_trebly_block = entries * entries + entries + direct_block_count;

    if (block < min_singly_block)
        return EXT4_TYPE_DIRECT_BLOCK;
    else if (block >= min_singly_block && block < min_doubly_block)
        return EXT4_TYPE_SINGLY_BLOCK;
    else if (block >= min_doubly_block && block < min_trebly_block)
        return EXT4_TYPE_DOUBLY_BLOCK;
    return EXT4_TYPE_TREBLY_BLOCK;
}

int Ext4GetExtent(ext4_superblock *Partition, ext4_inode *Inode, ext4_block_no LogicalBlock,
                  ext4_extent *Extent);

expected<ext4_block_no, int> ext4_get_block_from_inode(ext4_inode *ino, ext4_block_no block,
                                                       ext4_superblock *sb)
{
    if (ino->i_flags & EXT4_EXTENTS_FL)
        return ext4_emap_get_block(sb, ino, block);
    return ext4_bmap_get_block(sb, ino, block);
}

int ext4_prepare_write(inode *ino, struct page *page, size_t page_off, size_t offset, size_t len)
{
    auto end = offset + len;
    auto sb = ext4_superblock_from_inode(ino);

    auto bufs = block_buf_from_page(page);

    auto base_block = page_off / sb->block_size;
    auto nr_blocks = PAGE_SIZE / sb->block_size;

    if (ext4_get_inode_from_node(ino)->i_flags & EXT4_EXTENTS_FL)
        return -EIO;

    /* Handle pages that haven't been mapped yet */
    if (!bufs)
    {
        auto curr_off = 0;

        for (size_t i = 0; i < nr_blocks; i++)
        {
            struct block_buf *b = nullptr;
            if (!(b = page_add_blockbuf(page, curr_off)))
            {
                page_destroy_block_bufs(page);
                return -ENOMEM;
            }

            // printk("Adding block for page offset %u\n", b->page_off);

            b->block_nr = EXT4_FILE_HOLE_BLOCK;
            b->block_size = sb->block_size;
            b->dev = sb->s_bdev;

            curr_off += sb->block_size;
        }

        bufs = block_buf_from_page(page);
    }

    while (bufs)
    {
        if (bufs->page_off >= offset && bufs->page_off < end)
        {
            auto relative_block = bufs->page_off / sb->block_size;

            auto block_number = bufs->block_nr;

            if (block_number == EXT4_FILE_HOLE_BLOCK)
            {
                auto res = ext4_bmap_create_path(ino, base_block + relative_block, sb);
                // printk("creating path for poff %u file off %lu\n", bufs->page_off, offset);

                if (res.has_error())
                    return res.error();

                bufs->block_nr = res.value();
            }
        }

        bufs = bufs->next;
    }

    return 0;
}

int ext4_truncate(size_t len, inode *ino);
int ext4_truncate_inode_blocks(size_t new_len, inode *ino);

void ext4_free_inode_space(inode *inode_, ext4_superblock *fs)
{
    ext4_truncate_inode_blocks(0, inode_);
    assert(inode_->i_blocks == 0);
}

/**
 * @brief Checks if the ext4 inode has data blocks.
 * In ext4, several types of inodes (namely, symlinks and devices) can simply only have
 * inline data.
 *
 * @param ino     Pointer to the inode struct
 * @param raw_ino Pointer to the ext4 inode
 * @param sb      Pointer to the ext4 superblock
 * @return True if it has data blocks, else false.
 */
bool ext4_has_data_blocks(inode *ino, ext4_inode *raw_ino, ext4_superblock *sb)
{
    int ea_blocks = raw_ino->i_file_acl ? (sb->block_size >> 9) : 0;
    return ino->i_blocks - ea_blocks != 0;
}

int ext4_truncate_inode_blocks(size_t new_len, inode *ino)
{
    auto sb = ext4_superblock_from_inode(ino);
    auto raw_inode = ext4_get_inode_from_node(ino);

    // If the inode only has inline data, just return success.
    if (!ext4_has_data_blocks(ino, raw_inode, sb))
    {
        return 0;
    }

    if (raw_inode->i_flags & EXT4_EXTENTS_FL)
    {
        // TODO: Implement
        return -EIO;
    }

    return ext4_bmap_truncate_inode_blocks(new_len, ino);
}

int ext4_truncate(size_t len, inode *ino)
{
    int st = 0;

#if 0
	printk("truncating to %lu\n", len);
#endif

    if (ino->i_size > len)
    {
        if ((st = ext4_truncate_inode_blocks(len, ino)) < 0)
        {
            return st;
        }
    }

    /* **fallthrough**
     * The space freeing code will need this anyway, because you'll need to mark the inode dirty.
     */
    ino->i_size = len;
    vmo_truncate(ino->i_pages, len, VMO_TRUNCATE_DONT_PUNCH);
    inode_mark_dirty(ino);
    return st;
}

int ext4_ftruncate(size_t len, file *f)
{
    return ext4_truncate(len, f->f_ino);
}
