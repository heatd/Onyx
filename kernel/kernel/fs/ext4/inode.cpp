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

/* Inspired by linux's ext4_block_to_path, essentially does something like it. */
unsigned int ext4_get_block_path(ext4_superblock *sb, ext4_block_no offsets[4],
                                 ext4_block_no block_nr)
{
    unsigned int type = ext4_detect_block_type(block_nr, sb);
    const unsigned int entries = (sb->block_size / sizeof(uint32_t));
    unsigned int min_singly_block = direct_block_count;
    unsigned int min_doubly_block = entries + direct_block_count;
    unsigned int min_trebly_block = entries * entries + entries + direct_block_count;
    unsigned int idx = 0;

    if (type == EXT4_TYPE_DIRECT_BLOCK)
        offsets[idx++] = block_nr;
    else if (type == EXT4_TYPE_SINGLY_BLOCK)
    {
        offsets[idx++] = EXT4_IND_BLOCK;
        offsets[idx++] = block_nr - min_singly_block;
    }
    else if (type == EXT4_TYPE_DOUBLY_BLOCK)
    {
        block_nr -= min_doubly_block;

        unsigned int doubly_table_index = block_nr >> sb->entry_shift;
        unsigned int singly_table_index = block_nr & (entries - 1);

        offsets[idx++] = EXT4_DIND_BLOCK;
        offsets[idx++] = doubly_table_index;
        offsets[idx++] = singly_table_index;
    }
    else if (type == EXT4_TYPE_TREBLY_BLOCK)
    {
        block_nr -= min_trebly_block;
        unsigned int trebly_table_index = block_nr >> (sb->entry_shift * 2);
        unsigned int doubly_table_index = (block_nr >> sb->entry_shift) & (entries - 1);
        unsigned int singly_table_index = block_nr & (entries - 1);

        offsets[idx++] = EXT4_TIND_BLOCK;
        offsets[idx++] = trebly_table_index;
        offsets[idx++] = doubly_table_index;
        offsets[idx++] = singly_table_index;
    }

    return idx;
}

expected<ext4_block_no, int> ext4_get_block_from_inode(ext4_inode *ino, ext4_block_no block,
                                                       ext4_superblock *sb)
{
    ext4_block_no offsets[4];

    unsigned int len = ext4_get_block_path(sb, offsets, block);
    uint32_t *curr_block = ino->i_data;
    auto_block_buf buf;
    ext4_block_no dest_block_nr = 0;

    for (unsigned int i = 0; i < len; i++)
    {
        ext4_block_no off = offsets[i];

        /* We have to check if we're the last level, as to not read the dest block */
        if (i + 1 != len)
        {
            auto b = curr_block[off];

            if (b == EXT4_ERR_INV_BLOCK)
                return EXT4_ERR_INV_BLOCK;

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

expected<ext4_block_no, int> ext4_create_path(struct inode *ino, ext4_block_no block,
                                              ext4_superblock *sb)
{
    auto preferred_bg = ext4_inode_number_to_bg(ino->i_inode, sb);
    auto raw_inode = ext4_get_inode_from_node(ino);

    ext4_block_no offsets[4];

    unsigned int len = ext4_get_block_path(sb, offsets, block);
    uint32_t *curr_block = raw_inode->i_data;
    auto_block_buf buf;
    ext4_block_no dest_block_nr = 0;

    for (unsigned int i = 0; i < len; i++)
    {
        ext4_block_no off = offsets[i];

        /* We have to check if we're the last level, as to not read the dest block */
        if (i + 1 != len && len != 1)
        {
            auto b = curr_block[off];

            bool should_zero_block = false;

            if (b == EXT4_ERR_INV_BLOCK)
            {
                auto block = sb->allocate_block(preferred_bg);
                if (block == EXT4_ERR_INV_BLOCK)
                {
                    return unexpected<int>{-ENOSPC};
                }

                should_zero_block = true;

                b = curr_block[off] = block;

                ino->i_blocks += sb->block_size >> 9;

                if (buf)
                    block_buf_dirty(buf);
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
                block_buf_dirty(buf);
            }
        }
        else
        {
            dest_block_nr = curr_block[off];

            if (dest_block_nr == EXT4_FILE_HOLE_BLOCK)
            {
                auto block = sb->allocate_block();
                if (block == EXT4_ERR_INV_BLOCK)
                    return unexpected<int>{-ENOSPC};

                dest_block_nr = curr_block[off] = block;

                ino->i_blocks += sb->block_size >> 9;
                // printk("Block: %u\n", block);
                // printk("Iblocks %lu\n", ino->i_blocks);
                inode_update_ctime(ino);
                inode_mark_dirty(ino);
            }
        }
    }

    return dest_block_nr;
}

int ext4_prepare_write(inode *ino, struct page *page, size_t page_off, size_t offset, size_t len)
{
    auto end = offset + len;
    auto sb = ext4_superblock_from_inode(ino);

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
                auto res = ext4_create_path(ino, base_block + relative_block, sb);
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
int ext4_free_space(size_t new_len, inode *ino);

void ext4_free_inode_space(inode *inode_, ext4_superblock *fs)
{
    ext4_free_space(0, inode_);
    assert(inode_->i_blocks == 0);
}

struct ext4_block_coords
{
    ext4_block_no coords[4];
    int size;

    ext4_block_coords() : coords{0, 0, 0, 0}
    {
    }
    bool operator==(const ext4_block_coords &rhs) const
    {
        return coords[0] == rhs.coords[0] && coords[1] == rhs.coords[1] &&
               coords[2] == rhs.coords[2] && coords[3] == rhs.coords[3];
    }

    ext4_block_no &operator[](int idx)
    {
        return coords[idx];
    }

    size_t to_offset(const ext4_superblock *sb) const
    {
        /* Essentially this function mirrors ext4_get_block_path. I hope it's correct. */
        if (size == 1)
            return coords[0] << sb->block_size_shift;

        const unsigned int entries = (sb->block_size / sizeof(uint32_t));
        unsigned int min_singly_block = direct_block_count;
        unsigned int min_doubly_block = entries + direct_block_count;
        unsigned int min_trebly_block = entries * entries + entries + direct_block_count;

        if (size == 2)
        {
            return (coords[1] + min_singly_block) << sb->entry_shift;
        }
        else if (size == 3)
        {
            auto block_number = coords[2] << sb->entry_shift | coords[1];

            return (block_number + min_doubly_block) << sb->entry_shift;
        }
        else if (size == 4)
        {
            return ((coords[3] << (sb->entry_shift * 2) |
                     ((coords[2] << sb->entry_shift) & (entries - 1)) |
                     (coords[1] & (entries - 1))) +
                    min_trebly_block)
                   << sb->entry_shift;
        }
        else
            __builtin_unreachable();
    }
};

enum class ext4_trunc_result
{
    continue_trunc = 0,
    stop,
};

expected<ext4_trunc_result, int> ext4_trunc_indirect_block(ext4_block_no block,
                                                           unsigned int indirection_level,
                                                           const ext4_block_coords &boundary,
                                                           ext4_block_coords &curr_coords,
                                                           inode *ino, ext4_superblock *sb)
{
    auto block_off = curr_coords.to_offset(sb);

    if (indirection_level == 0)
    {
        if (curr_coords == boundary)
            return ext4_trunc_result::stop;

#if 0
		printk("Freeing block off %lu\n", block_off);
		printk("coords %u\n", curr_coords.coords[0]);
#endif
        inode_truncate_range(ino, block_off, block_off + sb->block_size);

        // printk("Iblocks %lu\n", ino->i_blocks);

        return ext4_trunc_result::continue_trunc;
    }

    auto_block_buf buf = sb_read_block(sb, block);
    if (!buf)
    {
        sb->error("I/O error");
        return unexpected<int>{-EIO};
    }

    buf_dirty_trigger dirty_trig{buf};

    uint32_t *blockbuf = (uint32_t *) block_buf_data(buf);

    unsigned int nr_entries = sb->block_size / sizeof(uint32_t);

    /* The basic algorithm for this is: We start from the end of the table,
     * and we keep going backwards until we either reach a stop/error, or we run out of table.
     * If we don't reach a stop, we free the block/block table
     * under us (check the indirection_level check).
     */

    for (int i = nr_entries - 1; i >= 0; i--)
    {
        curr_coords.coords[indirection_level] = i;

        if (curr_coords == boundary)
            return ext4_trunc_result::stop;

        if (blockbuf[i] == EXT4_FILE_HOLE_BLOCK)
            continue;

        if (indirection_level != 1)
        {
            auto st = ext4_trunc_indirect_block(blockbuf[i], indirection_level - 1, boundary,
                                                curr_coords, ino, sb);

            if (st.has_error())
                return unexpected<int>{st.error()};
            else if (st.value() == ext4_trunc_result::stop)
                return st;

            sb->free_block(blockbuf[i]);
            ino->i_blocks -= sb->block_size >> 9;
            blockbuf[i] = 0;
        }
        else
        {
            inode_truncate_range(ino, block_off, block_off + sb->block_size);
            sb->free_block(blockbuf[i]);
            ino->i_blocks -= sb->block_size >> 9;
            // printk("Iblocks %lu\n", ino->i_blocks);
            blockbuf[i] = 0;
        }
    }

    /* If we got here, we've cleared the whole table and as such we don't need to dirty it
     * since we're going to be free'd anyway by our caller.
     */

    dirty_trig.do_not_dirty();

    return ext4_trunc_result::continue_trunc;
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

int ext4_free_space(size_t new_len, inode *ino)
{
    auto sb = ext4_superblock_from_inode(ino);
    auto raw_inode = ext4_get_inode_from_node(ino);

    // If the inode only has inline data, just return success.
    if (!ext4_has_data_blocks(ino, raw_inode, sb))
    {
        return 0;
    }

    ext4_block_coords curr_coords{};

    ext4_block_coords boundary_coords;

    auto boundary_block = cul::align_down2(new_len - 1, sb->block_size) >> sb->block_size_shift;

    /* We don't have a boundary block if we're truncating to zero. See below. */
    if (new_len == 0)
        boundary_block = 0;

    auto len = ext4_get_block_path(sb, boundary_coords.coords, boundary_block);
    boundary_coords.size = len;

    for (int i = EXT4_NR_BLOCKS - 1; i != 0; i--)
    {
        int indirection_level = 3;
        if (i < EXT4_IND_BLOCK)
        {
            indirection_level = 0;
            curr_coords.size = 1;
        }
        else if (i == EXT4_IND_BLOCK)
        {
            indirection_level = 1;
            curr_coords.size = 2;
        }
        else if (i == EXT4_DIND_BLOCK)
        {
            indirection_level = 2;
            curr_coords.size = 3;
        }
        else if (i == EXT4_TIND_BLOCK)
        {
            indirection_level = 3;
            curr_coords.size = 4;
        }

        curr_coords[0] = i;
        curr_coords[1] = curr_coords[2] = curr_coords[3] = 0;

        /* Test this here since the EXT4_FILE_HOLE_BLOCK check may elide the one inside
         * ext4_trunc_indirect_block and because of that we start deleting blocks before the file
         * hole.
         */
        if (curr_coords == boundary_coords)
            break;

        auto block = raw_inode->i_data[i];

        if (block == EXT4_FILE_HOLE_BLOCK)
            continue;

        auto res = ext4_trunc_indirect_block(block, indirection_level, boundary_coords, curr_coords,
                                             ino, sb);

        if (res.has_error())
        {
            ERROR("ext4", "Error truncating file: %d\n", res.error());
            sb->error("Error truncating file");
            return res.error();
        }
        else if (res.value() == ext4_trunc_result::stop)
            break;
        else
        {
            /* If we're told to continue going down the tables, we'll remove this
             * one from i_data since it's been freed.
             */
            sb->free_block(block);
            ino->i_blocks -= sb->block_size >> 9;
            raw_inode->i_data[i] = EXT4_FILE_HOLE_BLOCK;
        }
    }

    if (new_len == 0)
    {
        /* If new_len is zero, we're going to get told to stop at (0, 0, 0, 0) even though
         * we want to delete that block too, so do so right now.
         */

        if (raw_inode->i_data[0])
        {
            sb->free_block(raw_inode->i_data[0]);
            inode_truncate_range(ino, 0, sb->block_size);
            ino->i_blocks = 0;
            // printk("zero Iblocks %lu\n", ino->i_blocks);
            raw_inode->i_data[0] = 0;
        }
    }

    if (new_len & (sb->block_size - 1))
    {
        auto page_off = new_len;
        inode_truncate_range(ino, page_off, ino->i_size);
    }

    return 0;
}

int ext4_truncate(size_t len, inode *ino)
{
    int st = 0;

#if 0
	printk("truncating to %lu\n", len);
#endif

    if (ino->i_size > len)
    {
        if ((st = ext4_free_space(len, ino)) < 0)
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
