/*
 * Copyright (c) 2017 - 2024 Pedro Falcato
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

#include "ext2.h"

#include <onyx/utility.hpp>

void ext2_set_inode_size(struct ext2_inode *inode, size_t size)
{
    inode->i_size_hi = size >> 32;
    inode->i_size_lo = size & 0xFFFFFFFF;
}

unsigned int ext2_detect_block_type(uint32_t block, struct ext2_superblock *fs)
{
    const unsigned int entries = (fs->block_size / sizeof(uint32_t));
    unsigned int min_singly_block = direct_block_count;
    unsigned int min_doubly_block = entries + direct_block_count;
    unsigned int min_trebly_block = entries * entries + entries + direct_block_count;

    if (block < min_singly_block)
        return EXT2_TYPE_DIRECT_BLOCK;
    else if (block >= min_singly_block && block < min_doubly_block)
        return EXT2_TYPE_SINGLY_BLOCK;
    else if (block >= min_doubly_block && block < min_trebly_block)
        return EXT2_TYPE_DOUBLY_BLOCK;
    return EXT2_TYPE_TREBLY_BLOCK;
}

/* Inspired by linux's ext2_block_to_path, essentially does something like it. */
unsigned int ext2_get_block_path(ext2_superblock *sb, ext2_block_no offsets[4],
                                 ext2_block_no block_nr)
{
    unsigned int type = ext2_detect_block_type(block_nr, sb);
    const unsigned int entries = (sb->block_size / sizeof(uint32_t));
    unsigned int min_singly_block = direct_block_count;
    unsigned int min_doubly_block = entries + direct_block_count;
    unsigned int min_trebly_block = entries * entries + entries + direct_block_count;
    unsigned int idx = 0;

    if (type == EXT2_TYPE_DIRECT_BLOCK)
        offsets[idx++] = block_nr;
    else if (type == EXT2_TYPE_SINGLY_BLOCK)
    {
        offsets[idx++] = EXT2_IND_BLOCK;
        offsets[idx++] = block_nr - min_singly_block;
    }
    else if (type == EXT2_TYPE_DOUBLY_BLOCK)
    {
        block_nr -= min_doubly_block;

        unsigned int doubly_table_index = block_nr >> sb->entry_shift;
        unsigned int singly_table_index = block_nr & (entries - 1);

        offsets[idx++] = EXT2_DIND_BLOCK;
        offsets[idx++] = doubly_table_index;
        offsets[idx++] = singly_table_index;
    }
    else if (type == EXT2_TYPE_TREBLY_BLOCK)
    {
        block_nr -= min_trebly_block;
        unsigned int trebly_table_index = block_nr >> (sb->entry_shift * 2);
        unsigned int doubly_table_index = (block_nr >> sb->entry_shift) & (entries - 1);
        unsigned int singly_table_index = block_nr & (entries - 1);

        offsets[idx++] = EXT2_TIND_BLOCK;
        offsets[idx++] = trebly_table_index;
        offsets[idx++] = doubly_table_index;
        offsets[idx++] = singly_table_index;
    }

    return idx;
}

expected<ext2_block_no, int> ext2_get_block_from_inode(ext2_inode *ino, ext2_block_no block,
                                                       ext2_superblock *sb)
{
    ext2_block_no offsets[4];

    unsigned int len = ext2_get_block_path(sb, offsets, block);
    uint32_t *curr_block = ino->i_data;
    auto_block_buf buf;
    ext2_block_no dest_block_nr = 0;

    for (unsigned int i = 0; i < len; i++)
    {
        ext2_block_no off = offsets[i];

        /* We have to check if we're the last level, as to not read the dest block */
        if (i + 1 != len)
        {
            auto b = curr_block[off];

            if (b == EXT2_ERR_INV_BLOCK)
                return EXT2_ERR_INV_BLOCK;

            buf = sb_read_block(sb, b);
            if (!buf)
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

expected<ext2_block_no, int> ext2_create_path(struct inode *ino, ext2_block_no block,
                                              ext2_superblock *sb)
{
    auto preferred_bg = ext2_inode_number_to_bg(ino->i_inode, sb);
    auto raw_inode = ext2_get_inode_from_node(ino);

    ext2_block_no offsets[4];

    unsigned int len = ext2_get_block_path(sb, offsets, block);
    uint32_t *curr_block = raw_inode->i_data;
    auto_block_buf buf;
    ext2_block_no dest_block_nr = 0;

    for (unsigned int i = 0; i < len; i++)
    {
        ext2_block_no off = offsets[i];

        /* We have to check if we're the last level, as to not read the dest block */
        if (i + 1 != len && len != 1)
        {
            auto b = curr_block[off];

            bool should_zero_block = false;

            if (b == EXT2_ERR_INV_BLOCK)
            {
                auto block = sb->allocate_block(preferred_bg);
                if (block == EXT2_ERR_INV_BLOCK)
                {
                    return unexpected<int>{-ENOSPC};
                }

                should_zero_block = true;

                b = curr_block[off] = block;

                ino->i_blocks += sb->block_size >> 9;

                if (buf)
                    block_buf_dirty_inode(buf, ino);
                else
                {
                    inode_update_ctime(ino);
                    inode_mark_dirty(ino);
                }
            }

            buf = sb_read_block(sb, b);
            if (!buf)
                return unexpected<int>{-errno};

            curr_block = static_cast<uint32_t *>(block_buf_data(buf));

            if (should_zero_block) [[unlikely]]
            {
                memset(curr_block, 0, sb->block_size);
                block_buf_dirty_inode(buf, ino);
            }
        }
        else
        {
            dest_block_nr = curr_block[off];

            if (dest_block_nr == EXT2_FILE_HOLE_BLOCK)
            {
                auto block = sb->allocate_block();
                if (block == EXT2_ERR_INV_BLOCK)
                    return unexpected<int>{-ENOSPC};

                dest_block_nr = curr_block[off] = block;

                ino->i_blocks += sb->block_size >> 9;
                if (buf)
                    block_buf_dirty_inode(buf, ino);
                else
                {
                    inode_update_ctime(ino);
                    inode_mark_dirty(ino);
                }
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

            b->block_nr = EXT2_FILE_HOLE_BLOCK;
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

            if (block_number == EXT2_FILE_HOLE_BLOCK)
            {
                auto res = ext2_create_path(ino, base_block + relative_block, sb);
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

int ext2_truncate(size_t len, inode *ino);
int ext2_free_space(size_t new_len, inode *ino);

void ext2_free_inode_space(inode *inode_, ext2_superblock *fs)
{
    ext2_free_space(0, inode_);
    assert(inode_->i_blocks == 0);
}

struct ext2_block_coords
{
    ext2_block_no coords[4];
    int size;

    ext2_block_coords() : coords{0, 0, 0, 0}
    {
    }
    bool operator==(const ext2_block_coords &rhs) const
    {
        return size == rhs.size && coords[0] == rhs.coords[0] && coords[1] == rhs.coords[1] &&
               coords[2] == rhs.coords[2] && coords[3] == rhs.coords[3];
    }

    ext2_block_no &operator[](int idx)
    {
        return coords[idx];
    }
};

/**
 * @brief Checks if the ext2 inode has data blocks.
 * In ext2, several types of inodes (namely, symlinks and devices) can simply only have
 * inline data.
 *
 * @param ino     Pointer to the inode struct
 * @param raw_ino Pointer to the ext2 inode
 * @param sb      Pointer to the ext2 superblock
 * @return True if it has data blocks, else false.
 */
bool ext2_has_data_blocks(inode *ino, ext2_inode *raw_ino, ext2_superblock *sb)
{
    int ea_blocks = raw_ino->i_file_acl ? (sb->block_size >> 9) : 0;
    return ino->i_blocks - ea_blocks != 0;
}

#define EXT2_TRUNCATED_FULLY     1
#define EXT2_TRUNCATED_PARTIALLY 0

int ext2_truncate_branch(ext2_block_no block, ext2_block_coords &curr_coords, struct inode *ino,
                         int indirection_level)
{
    DCHECK(block != EXT2_FILE_HOLE_BLOCK);
    auto sb = ext2_superblock_from_inode(ino);
    ext2_block_no *ind_block_data;
    unsigned int coord_idx = curr_coords.size - indirection_level - 1;
    bool partial_block = curr_coords.coords[coord_idx] != 0;

    if (coord_idx == 0)
    {
        /* Free the block */
        sb->free_block(block);
        ino->i_blocks -= sb->block_size >> 9;
        return EXT2_TRUNCATED_FULLY;
    }

    /* Indirect block paths.. */
    auto_block_buf buf = sb_read_block(sb, block);
    if (!buf)
    {
        sb->error("I/O error");
        return -EIO;
    }

    ind_block_data = (ext2_block_no *) block_buf_data(buf);

    unsigned int blocks_per_indirect = sb->block_size / sizeof(ext2_block_no);
    for (unsigned int i = curr_coords.coords[coord_idx]; i < blocks_per_indirect; i++)
    {
        ext2_block_no next_level = ind_block_data[i];
        if (next_level == EXT2_FILE_HOLE_BLOCK)
            continue;

        int st = ext2_truncate_branch(next_level, curr_coords, ino, indirection_level + 1);
        if (st < 0)
            return st;
        else if (st == EXT2_TRUNCATED_FULLY)
            ind_block_data[i] = 0;
        else if (st == EXT2_TRUNCATED_PARTIALLY)
        {
            partial_block = true;
            continue;
        }
    }

    /* Reset the coord */
    curr_coords.coords[coord_idx] = 0;
    if (partial_block)
        return EXT2_TRUNCATED_PARTIALLY;
    /* Truncated fully, we can free this block */
    /* Note: we must "forget" the inode block buf */
    block_buf_forget_inode(buf);
    sb->free_block(block);
    ino->i_blocks -= sb->block_size >> 9;
    return EXT2_TRUNCATED_FULLY;
}

int ext2_free_space(size_t new_len, inode *ino)
{
    auto sb = ext2_superblock_from_inode(ino);
    auto raw_inode = ext2_get_inode_from_node(ino);

    // If the inode only has inline data, just return success.
    if (!ext2_has_data_blocks(ino, raw_inode, sb))
        return 0;

    ext2_block_coords curr_coords;
    ext2_block_coords boundary_coords;

    auto boundary_block = cul::align_up2(new_len, sb->block_size) >> sb->block_size_shift;

    auto len = ext2_get_block_path(sb, boundary_coords.coords, boundary_block);
    boundary_coords.size = len;
    curr_coords = boundary_coords;

    for (unsigned int i = boundary_coords.coords[0]; i < EXT2_NR_BLOCKS;
         i++, curr_coords.coords[0]++)
    {
        DCHECK(curr_coords.coords[0] == i);
        if (i == EXT2_IND_BLOCK)
            curr_coords.size = 2;
        else if (i == EXT2_DIND_BLOCK)
            curr_coords.size = 3;
        else if (i == EXT2_TIND_BLOCK)
            curr_coords.size = 4;

        for (int j = curr_coords.size; j < 4; j++)
            DCHECK(curr_coords.coords[j] == 0);

        if (raw_inode->i_data[i] == 0)
            continue;

        int st = ext2_truncate_branch(raw_inode->i_data[i], curr_coords, ino, 0);
        if (st < 0)
            return st;
        else if (st == EXT2_TRUNCATED_PARTIALLY)
            continue;
        else if (st == EXT2_TRUNCATED_FULLY)
            raw_inode->i_data[i] = 0;
    }

    return 0;
}

int ext2_truncate(size_t len, inode *ino)
{
    int st = 0;

#if 0
	printk("truncating to %lu\n", len);
#endif

    if (ino->i_size > len)
    {
        if ((st = ext2_free_space(len, ino)) < 0)
        {
            return st;
        }
    }

    /* **fallthrough**
     * The space freeing code will need this anyway, because you'll need to mark the inode dirty.
     */
    ino->i_size = len;
    vmo_truncate(ino->i_pages, len, 0);
    inode_mark_dirty(ino);
    /* TODO: Update mtime and ctime, per POSIX */
    return st;
}

int ext2_ftruncate(size_t len, file *f)
{
    return ext2_truncate(len, f->f_ino);
}
