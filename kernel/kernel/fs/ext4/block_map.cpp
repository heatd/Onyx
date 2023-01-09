/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/log.h>

#include "ext4.h"

#include <onyx/expected.hpp>
/**
 * @brief Get the block path for bmap inodes
 *
 * @param sb Superblock
 * @param offsets Offsets
 * @param block_nr Logical block number
 * @return Number of entries in the block path
 */
unsigned int ext4_bmap_get_block_path(ext4_superblock *sb, ext4_block_no offsets[4],
                                      ext4_block_no block_nr)
{
    unsigned int type = ext4_detect_block_type(block_nr, sb);
    const unsigned int entries = (sb->block_size / sizeof(uint32_t));
    unsigned int min_singly_block = EXT4_DIRECT_BLOCK_COUNT;
    unsigned int min_doubly_block = entries + EXT4_DIRECT_BLOCK_COUNT;
    unsigned int min_trebly_block = entries * entries + entries + EXT4_DIRECT_BLOCK_COUNT;
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

/**
 * @brief Get the underlying block from a logical block, for a given inode
 *
 * @param sb Superblock
 * @param ino Inode
 * @param block Logical block
 * @return ext4 block, or a negative error number
 */
expected<ext4_block_no, int> ext4_bmap_get_block(ext4_superblock *sb, ext4_inode *ino,
                                                 ext4_block_no block)
{
    ext4_block_no offsets[4];

    unsigned int len = ext4_bmap_get_block_path(sb, offsets, block);
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

/**
 * @brief Create the path and allocate a block
 *
 * @param ino Inode
 * @param block Block to create the path too
 * @param sb Superblock
 * @return Allocated block number, or negative error number
 */
expected<ext4_block_no, int> ext4_bmap_create_path(inode *ino, ext4_block_no block,
                                                   ext4_superblock *sb)
{
    auto preferred_bg = ext4_inode_number_to_bg(ino->i_inode, sb);
    auto raw_inode = ext4_get_inode_from_node(ino);

    ext4_block_no offsets[4];

    unsigned int len = ext4_bmap_get_block_path(sb, offsets, block);
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
        unsigned int min_singly_block = EXT4_DIRECT_BLOCK_COUNT;
        unsigned int min_doubly_block = entries + EXT4_DIRECT_BLOCK_COUNT;
        unsigned int min_trebly_block = entries * entries + entries + EXT4_DIRECT_BLOCK_COUNT;

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
 * @brief Truncates inode blocks for bmap inodes
 *
 * @param new_len New length
 * @param ino Pointer to inode
 * @return 0 on success, negative error codes
 */
int ext4_bmap_truncate_inode_blocks(size_t new_len, inode *ino)
{
    auto sb = ext4_superblock_from_inode(ino);
    auto raw_inode = ext4_get_inode_from_node(ino);

    ext4_block_coords curr_coords{};

    ext4_block_coords boundary_coords;

    auto boundary_block = cul::align_down2(new_len - 1, sb->block_size) >> sb->block_size_shift;

    /* We don't have a boundary block if we're truncating to zero. See below. */
    if (new_len == 0)
        boundary_block = 0;

    auto len = ext4_bmap_get_block_path(sb, boundary_coords.coords, boundary_block);
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
