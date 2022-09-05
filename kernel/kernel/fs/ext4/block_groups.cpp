/*
 * Copyright (c) 2017 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdlib.h>

#include <onyx/compiler.h>
#include <onyx/crc32.h>
#include <onyx/limits.h>

#include "ext4.h"

/**
   Checks if the checksum of the block group descriptor is correct.
   @param[in]      Partition       Pointer to the opened EXT4 partition.
   @param[in]      BlockGroupDesc  Pointer to the block group descriptor.
   @param[in]      BlockGroupNum   Number of the block group.
   @return TRUE if checksum is correct, FALSE if there is corruption.
**/
bool ext4_verify_block_group_desc_csum(const ext4_superblock *Partition,
                                       const block_group_desc_t *BlockGroupDesc,
                                       ext4_block_group_no BlockGroupNum);

int ext4_block_group::init()
{
    auto bgdt_block_start = sb_->block_size == 1024 ? 2 : 1;
    auto bgdt_block = bgdt_block_start + ((sb_->desc_size * nr) / sb_->block_size);
    auto bgdt_offset = (sb_->desc_size * nr) % sb_->block_size;

    buf = sb_read_block(sb_, bgdt_block);
    if (!buf)
        return -ENOMEM;

    bgd = (block_group_desc_t *) ((char *) block_buf_data(buf) + bgdt_offset);

    if (!ext4_verify_block_group_desc_csum(sb_, bgd, nr))
    {
        sb_->error("Bad block group %u checksum\n", nr);
        return -EIO;
    }
    return 0;
}

/* This is the max reserved inode number, everything below it is reserved */
#define EXT4_UNDEL_DIR_INO 6

expected<ext4_inode_no, int> ext4_block_group::allocate_inode(ext4_superblock *sb)
{
    scoped_mutex g{inode_bitmap_lock};

    /* The inode and block bitmaps are guaranteed to a single block in size */
    auto_block_buf buf = sb_read_block(
        sb, EXT4_BLOCK_NR_FROM_HALFS(sb, bgd->bg_inode_bitmap_lo, bgd->bg_inode_bitmap_hi));

    if (!buf)
    {
        sb->error("Failed to read inode bitmap");
        return unexpected{-EIO};
    }

    auto bitmap = static_cast<unsigned long *>(block_buf_data(buf));

    auto bit = ext4_scan_zero(bitmap, sb->s_block_size);

    if (bit == SCAN_ZERO_NOT_FOUND)
        return unexpected{-ENOSPC};

    static constexpr auto bits_per_long = WORD_SIZE * CHAR_BIT;

    /* Set the corresponding bit */
    bitmap[bit / bits_per_long] |= (1UL << (bit % bits_per_long));
    /* Change the block group and superblock
       structures in order to reflect it */

    dec_unallocated_inodes();

    EXT4_ATOMIC_SUB(sb->sb->s_free_inodes_count, 1);
    /* Actually register the changes on disk */
    /* We give the bitmap priority here,
     * since there can be a disk failure or a
     * shutdown at any time,
     * and this is the most important part */

    block_buf_dirty(buf);
    ext4_dirty_sb(sb);

    return nr * sb->inodes_per_block_group + bit + 1;
}

expected<ext4_block_no, int> ext4_block_group::allocate_block(ext4_superblock *sb)
{
    scoped_mutex g{block_bitmap_lock};

    /* The inode and block bitmaps are guaranteed to a single block in size */
    auto_block_buf buf = sb_read_block(
        sb, EXT4_BLOCK_NR_FROM_HALFS(sb, bgd->bg_block_bitmap_lo, bgd->bg_block_bitmap_hi));

    if (!buf)
    {
        sb->error("Failed to read block bitmap");
        return unexpected{-EIO};
    }

    auto bitmap = static_cast<unsigned long *>(block_buf_data(buf));

    auto bit = ext4_scan_zero(bitmap, sb->s_block_size);

    if (bit == SCAN_ZERO_NOT_FOUND)
        return unexpected{-ENOSPC};

    static constexpr auto bits_per_long = WORD_SIZE * CHAR_BIT;

    /* Set the corresponding bit */
#if 0
	printk("Got bit %lu\n", bit);
	printk("setting %lu on word %lu\n", (bit % bits_per_long), bit / bits_per_long);
#endif

    bitmap[bit / bits_per_long] |= (1UL << (bit % bits_per_long));

    assert(ext4_scan_zero(bitmap, sb->s_block_size) != bit);

    /* Change the block group and superblock
       structures in order to reflect it */

    dec_unallocated_blocks();

    EXT4_ATOMIC_SUB(sb->sb->s_free_blocks_count, 1);
    /* Actually register the changes on disk */
    /* We give the bitmap priority here,
     * since there can be a disk failure or a
     * shutdown at any time,
     * and this is the most important part */

    block_buf_dirty(buf);
    ext4_dirty_sb(sb);

    return nr * sb->blocks_per_block_group + bit + sb->first_data_block();
}

void ext4_block_group::free_block(ext4_block_no block, ext4_superblock *sb)
{
    scoped_mutex g{block_bitmap_lock};

    // printk("freeing block %u\n", block);

    /* The inode and block bitmaps are guaranteed to a single block in size */
    auto_block_buf buf = sb_read_block(
        sb, EXT4_BLOCK_NR_FROM_HALFS(sb, bgd->bg_block_bitmap_lo, bgd->bg_block_bitmap_hi));

    if (!buf)
    {
        sb->error("Failed to read block bitmap");
        return;
    }

    auto bitmap = static_cast<uint8_t *>(block_buf_data(buf));

    auto bit = (block - sb->first_data_block()) % sb->blocks_per_block_group;
    auto byte_idx = bit / CHAR_BIT;
    auto bit_idx = bit % CHAR_BIT;

    /* Let's check for corruption, if it's already free we'll have to error. */
    if (!(bitmap[byte_idx] & (1 << bit_idx)))
    {
        sb->error("Corruption detected: Block already freed");
        return;
    }

    bitmap[byte_idx] &= ~(1 << bit_idx);

    block_buf_dirty(buf);

    inc_unallocated_blocks();

    EXT4_ATOMIC_ADD(sb->sb->s_free_blocks_count, 1);

    ext4_dirty_sb(sb);
}

void ext4_block_group::free_inode(ext4_inode_no inode, ext4_superblock *sb)
{
    scoped_mutex g{inode_bitmap_lock};

    /* The inode and block bitmaps are guaranteed to a single block in size */
    auto_block_buf buf = sb_read_block(
        sb, EXT4_BLOCK_NR_FROM_HALFS(sb, bgd->bg_inode_bitmap_lo, bgd->bg_inode_bitmap_hi));

    if (!buf)
    {
        sb->error("Failed to read inode bitmap");
        return;
    }

    auto bitmap = static_cast<uint8_t *>(block_buf_data(buf));

    auto bit = (inode - 1) % sb->inodes_per_block_group;
    auto byte_idx = bit / CHAR_BIT;
    auto bit_idx = bit % CHAR_BIT;

    /* Let's check for corruption, if it's already free we'll have to error. */
    if (!(bitmap[byte_idx] & (1 << bit_idx)))
    {
        sb->error("Corruption detected: Inode already freed");
        return;
    }

    bitmap[byte_idx] &= ~(1 << bit_idx);

    block_buf_dirty(buf);

    inc_unallocated_inodes();

    EXT4_ATOMIC_ADD(sb->sb->s_free_inodes_count, 1);

    ext4_dirty_sb(sb);
}

auto_block_buf ext4_block_group::get_inode_table(const ext4_superblock *sb, uint32_t off) const
{
    return sb_read_block(sb, get_itable_block(sb) + off);
}

ext4_block_no ext4_block_group::get_itable_block(const ext4_superblock *sb) const
{
    return EXT4_BLOCK_NR_FROM_HALFS(sb, bgd->bg_inode_table_lo, bgd->bg_inode_table_hi);
}

/**
   Calculates the checksum of the block group descriptor for METADATA_CSUM enabled filesystems.
   @param[in]      Partition       Pointer to the opened EXT4 partition.
   @param[in]      BlockGroupDesc  Pointer to the block group descriptor.
   @param[in]      BlockGroupNum   Number of the block group.
   @return The checksum.
**/
static uint16_t ext4_calculate_block_group_desc_csum_metadata_csum(
    const ext4_superblock *Partition, const block_group_desc_t *BlockGroupDesc,
    ext4_block_group_no BlockGroupNum)
{
    uint32_t Csum;
    uint16_t Dummy = 0;

    Csum = ext4_calculate_csum(Partition, &BlockGroupNum, sizeof(BlockGroupNum),
                               Partition->initial_seed);
    Csum = ext4_calculate_csum(Partition, BlockGroupDesc, offsetof(block_group_desc_t, bg_checksum),
                               Csum);
    Csum = ext4_calculate_csum(Partition, &Dummy, sizeof(Dummy), Csum);
    Csum = ext4_calculate_csum(
        Partition, &BlockGroupDesc->bg_block_bitmap_hi,
        Partition->desc_size - offsetof(block_group_desc_t, bg_block_bitmap_hi), Csum);
    return (uint16_t) Csum;
}

/**
   Calculates the checksum of the block group descriptor for GDT_CSUM enabled filesystems.
   @param[in]      Partition       Pointer to the opened EXT4 partition.
   @param[in]      BlockGroupDesc  Pointer to the block group descriptor.
   @param[in]      BlockGroupNum   Number of the block group.
   @return The checksum.
**/
static uint16_t ext4_calculate_block_group_desc_csum_gdt_csum(
    const ext4_superblock *Partition, const block_group_desc_t *BlockGroupDesc,
    ext4_block_group_no BlockGroupNum)
{
    uint16_t Csum;
    uint16_t Dummy = 0;

    Csum = crc16_calculate(Partition->sb->s_uuid, 16, 0);
    Csum = crc16_calculate(&BlockGroupNum, sizeof(BlockGroupNum), Csum);
    Csum = crc16_calculate(BlockGroupDesc, offsetof(block_group_desc_t, bg_checksum), Csum);
    Csum = crc16_calculate(&Dummy, sizeof(Dummy), Csum);
    Csum = crc16_calculate(&BlockGroupDesc->bg_block_bitmap_hi,
                           Partition->desc_size - offsetof(block_group_desc_t, bg_block_bitmap_hi),
                           Csum);
    return Csum;
}

/**
   Calculates the checksum of the block group descriptor.
   @param[in]      Partition       Pointer to the opened EXT4 partition.
   @param[in]      BlockGroupDesc  Pointer to the block group descriptor.
   @param[in]      BlockGroupNum   Number of the block group.
   @return The checksum.
**/
uint16_t ext4_calculate_block_group_desc_csum(const ext4_superblock *Partition,
                                              const block_group_desc_t *BlockGroupDesc,
                                              ext4_block_group_no BlockGroupNum)
{
    if (EXT4_HAS_METADATA_CSUM(Partition))
    {
        return ext4_calculate_block_group_desc_csum_metadata_csum(Partition, BlockGroupDesc,
                                                                  BlockGroupNum);
    }
    else if (EXT4_HAS_GDT_CSUM(Partition))
    {
        return ext4_calculate_block_group_desc_csum_gdt_csum(Partition, BlockGroupDesc,
                                                             BlockGroupNum);
    }

    return 0;
}

/**
   Checks if the checksum of the block group descriptor is correct.
   @param[in]      Partition       Pointer to the opened EXT4 partition.
   @param[in]      BlockGroupDesc  Pointer to the block group descriptor.
   @param[in]      BlockGroupNum   Number of the block group.
   @return TRUE if checksum is correct, FALSE if there is corruption.
**/
bool ext4_verify_block_group_desc_csum(const ext4_superblock *Partition,
                                       const block_group_desc_t *BlockGroupDesc,
                                       ext4_block_group_no BlockGroupNum)
{
    if (!EXT4_HAS_METADATA_CSUM(Partition) && !EXT4_HAS_GDT_CSUM(Partition))
    {
        return true;
    }

    return ext4_calculate_block_group_desc_csum(Partition, BlockGroupDesc, BlockGroupNum) ==
           BlockGroupDesc->bg_checksum;
}

void ext4_block_group::dirty()
{
    if (EXT4_HAS_METADATA_CSUM(sb_))
        bgd->bg_checksum = ext4_calculate_block_group_desc_csum(sb_, bgd, nr);
    block_buf_dirty(buf);
}
