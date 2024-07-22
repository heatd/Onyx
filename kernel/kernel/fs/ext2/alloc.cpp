/*
 * Copyright (c) 2017 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include <onyx/compiler.h>
#include <onyx/cred.h>
#include <onyx/panic.h>

#include "ext2.h"

/**
 * @brief Alocates an inode
 *
 * @return Expected consisting of a pair of the inode number and a ext2_inode *, or an
 * unexpected negative error code
 */
expected<cul::pair<ext2_inode_no, ext2_inode *>, int> ext2_superblock::allocate_inode()
{
    /* TODO: Add a good algorithm that can locally pick an inode */

    /* If we just don't have any inodes available, error */
    if (sb->s_free_inodes_count == 0) [[unlikely]]
        return unexpected<int>{-ENOSPC};

    for (auto &bg : block_groups)
    {
        if (bg.get_bgd()->unallocated_inodes_in_group > 0)
        {
            auto res = bg.allocate_inode(this);
            if (res.has_error())
                continue;
            else
            {
                ext2_inode *ino = get_inode(res.value());
                if (!ino)
                {
                    bg.free_inode(res.value(), this);
                    return unexpected{-errno};
                }

                memset(ino, 0, inode_size);

                update_inode(ino, res.value(), false);

                return cul::pair{res.value(), ino};
            }
        }
    }

    return unexpected<int>{-ENOSPC};
}

/**
 * @brief Frees the inode
 *
 * @param ino Inode number
 */
void ext2_superblock::free_inode(ext2_inode_no inode)
{
    uint32_t bg_no = ext2_inode_number_to_bg(inode, this);

    assert(bg_no <= number_of_block_groups);

    block_groups[bg_no].free_inode(inode, this);
}

ext2_block_no ext2_superblock::try_allocate_block_from_bg(ext2_block_group_no nr)
{
    if (nr >= number_of_block_groups)
    {
        panic("Invalid block group number %u(out of %u bgs)", nr, number_of_block_groups);
    }

    auto &bg = block_groups[nr];

    if (bg.get_bgd()->unallocated_blocks_in_group == 0)
        return EXT2_ERR_INV_BLOCK;

    auto res = bg.allocate_block(this);

#if 0
	printk("Allocated block %u from bg %u\n", res.value_or(EXT2_ERR_INV_BLOCK), nr);
#endif
    return res.value_or(EXT2_ERR_INV_BLOCK);
}

/**
 * @brief Allocates a block, taking into account the preferred block group
 *
 * @param preferred The preferred block group. If -1, no preferrence
 * @return Block number, or EXT2_ERR_INV_BLOCK if we couldn't allocate one.
 */
ext2_block_no ext2_superblock::allocate_block(ext2_block_group_no preferred)
{
    if (sb->s_free_blocks_count == 0) [[unlikely]]
        return EXT2_ERR_INV_BLOCK;

    if (sb->s_free_blocks_count <= sb->s_r_blocks_count) [[unlikely]]
    {
        auto c = creds_get();

        bool may_use_blocks = c->euid == sb->s_def_resuid || c->egid == sb->s_def_resgid;

        creds_put(c);

        if (!may_use_blocks)
            return EXT2_ERR_INV_BLOCK;
    }

    if (preferred == (ext2_block_group_no) -1)
        preferred = 0;

    /* Our algorithm works like this: We take the preferred block group, and then we'll
     * iterate the block groups inside-out, trying them according to the distance.
     */

    auto max_block_group = this->number_of_block_groups - 1;
    int dist_start = preferred;
    int dist_end = max_block_group - preferred;

    auto max_distance = cul::max(dist_start, dist_end);
    ext2_block_no block = EXT2_ERR_INV_BLOCK;

    for (int dist = 0; dist <= max_distance; dist++, dist_start--, dist_end--)
    {
        /* We're testing against dist here because if dist is zero(opening round)
         * we'll only need to try once, since both tries will point to the same block group.
         */
        if (dist && dist_start >= 0)
            block = try_allocate_block_from_bg(preferred - dist);

        if (block != EXT2_ERR_INV_BLOCK)
            return block;

        if (dist_end >= 0)
            block = try_allocate_block_from_bg(preferred + dist);

        if (block != EXT2_ERR_INV_BLOCK)
            return block;
    }

    return EXT2_ERR_INV_BLOCK;
}

/**
 * @brief Frees a block
 *
 * @param block Block number to free
 */
void ext2_superblock::free_block(ext2_block_no block)
{
    assert(block != EXT2_ERR_INV_BLOCK);

    auto block_group = (block - first_data_block()) / blocks_per_block_group;

    assert(block_group < number_of_block_groups);

    block_groups[block_group].free_block(block, this);
}
