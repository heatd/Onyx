/*
 * Copyright (c) 2017 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/crc32.h>

#include "ext4.h"

/**
   Calculates the superblock's checksum.
   @param[in] sb           Pointer to the superblock.
   @return The superblock's checksum.
**/
static uint32_t ext4_calculate_sb_csum(const ext4_superblock *sb)
{
    return ext4_calculate_csum(sb, sb->sb, offsetof(superblock_t, s_checksum), ~0U);
}

void ext4_dirty_sb(ext4_superblock *fs)
{
    if (EXT4_HAS_METADATA_CSUM(fs))
        fs->sb->s_checksum = ext4_calculate_sb_csum(fs);
    block_buf_dirty(fs->sb_bb);
}

/**
   Verifies that the superblock's checksum is valid.
   @param[in] sb           Pointer to the superblock.
   @return true if valid, else false
**/
bool ext4_verify_sb_csum(const ext4_superblock *sb)
{
    if (!EXT4_HAS_METADATA_CSUM(sb))
    {
        return true;
    }

    return sb->sb->s_checksum == ext4_calculate_sb_csum(sb);
}

/**
 * @brief Reads metadata blocks from the filesystem using sb_read_block
 *
 * @param block Starting block
 * @param number_of_blocks Number of blocks
 * @param bufs Pointer to an array of N auto_block_buf's
 * @return 0 on success, negative error codes
 */
int ext4_superblock::read_blocks(ext4_block_no block, ext4_block_no number_of_blocks,
                                 auto_block_buf *bufs)
{
    for (ext4_block_no i = 0; i < number_of_blocks; i++)
    {
        bufs[i] = sb_read_block(this, block + i);
        if (!bufs[i])
        {
            for (ext4_block_no j = 0; j < i; j++)
            {
                bufs[j].reset(nullptr);
                return -errno;
            }
        }
    }

    return 0;
}

/**
 * @brief Read an ext4_inode from disk
 *
 * @param nr The inode number
 * @param check_csum If the function should check the checksum
 * @return A pointer to the inode number
 */
ext4_inode *ext4_superblock::get_inode(ext4_inode_no inode, bool check_csum) const
{
    uint32_t bg_no = ext4_inode_number_to_bg(inode, this);
    uint32_t index = (inode - 1) % inodes_per_block_group;
    uint32_t inodes_per_block = block_size / inode_size;
    uint32_t block = index / inodes_per_block;
    uint32_t off = (index % inodes_per_block) * inode_size;

    assert(bg_no < number_of_block_groups);

    const auto &bg = block_groups[bg_no];

    auto buf = bg.get_inode_table(this, block);
    if (!buf)
    {
        error("Error reading inode table.");
        printk("Tried to read block %u\n", bg.get_bgd()->bg_inode_table_lo);
        return nullptr;
    }

    // Why do we do this?
    // Well, there are some fields we may want to access for the moment, such as i_extra_isize
    // which require the structure to be properly sized. As such, we allocate min(our_struct,
    // inode_size) and zero the difference if our struct is larger.
    // Note that we could take care of this inside ext4_inode_info or something. I'm not too sure I
    // want to do that.
    auto alloc_size = min(inode_size, (uint16_t) sizeof(ext4_inode));
    ext4_inode *ino = (ext4_inode *) malloc(alloc_size);

    if (!ino)
        return nullptr;

    ext4_inode *on_disk = (ext4_inode *) ((char *) block_buf_data(buf) + off);

    if (check_csum && !ext4_check_inode_csum(this, on_disk, inode))
    {
        free(ino);
        error("Inode %u has a bad checksum", inode);
        errno = EIO;
        return nullptr;
    }

    memcpy(ino, on_disk, inode_size);

    if (alloc_size > inode_size)
    {
        // Zero the tail of the inode
        memset((char *) ino + inode_size, 0, alloc_size - inode_size);
    }

    return ino;
}

/**
 * @brief Updates an inode on disk
 *
 * @param ino Pointer to ext4_inode
 * @param inode_no Inode number
 */
void ext4_superblock::update_inode(const ext4_inode *ino, ext4_inode_no inode_no)
{
    assert(inode_no != 0);
    uint32_t bg_no = ext4_inode_number_to_bg(inode_no, this);
    uint32_t index = (inode_no - 1) % inodes_per_block_group;
    uint32_t inodes_per_block = block_size / inode_size;
    uint32_t block = index / inodes_per_block;
    uint32_t off = (index % inodes_per_block) * inode_size;

    assert(bg_no < number_of_block_groups);

    const auto &bg = block_groups[bg_no];

    auto buf = bg.get_inode_table(this, block);
    if (!buf)
    {
        error("Error reading inode table.");
        printk("Tried to read block %u\n", bg.get_bgd()->bg_inode_table_lo);
        return;
    }

    ext4_inode *on_disk = (ext4_inode *) ((char *) block_buf_data(buf) + off);

    memcpy(on_disk, ino, inode_size);

    ext4_update_inode_csum(this, on_disk, inode_no);

    block_buf_dirty(buf);
}

struct inode *ext4_load_inode_from_disk(uint32_t inum, struct ext4_superblock *fs)
{
    struct ext4_inode *inode = fs->get_inode(inum);
    if (!inode)
        return nullptr;

    struct inode *node = ext4_fs_ino_to_vfs_ino(inode, inum, fs);
    if (!node)
    {
        free(inode);
        return errno = ENOMEM, nullptr;
    }

    return node;
}

/**
 * @brief Reports a filesystem error
 *
 * @param str Error Message
 */
void ext4_superblock::error(const char *str, ...) const
{
    char *buf = (char *) malloc(512);
    bool stack = false;
    if (!buf)
    {
        // Cheers, I hate this. But lets prioritize error reporting
        stack = true;
        buf = (char *) alloca(200);
    }

    va_list va;
    va_start(va, str);
    int st = vsnprintf(buf, stack ? 200 : 512, str, va);

    if (st < 0)
        strcpy(buf, "<bad error format string>");

    va_end(va);
    printk("ext4 error: %s\n", buf);

    if (!stack)
        free(buf);

    sb->s_state = EXT4_ERROR_FS;
    block_buf_dirty(sb_bb);
    block_buf_writeback(sb_bb);

    if (sb->s_errors == EXT4_ERRORS_CONTINUE)
        return;
    else if (sb->s_errors == EXT4_ERRORS_PANIC)
        panic("ext4: Panic from previous filesystem error");

    /* TODO: Add (re)mouting read-only */
}

/**
 * @brief Does statfs
 *
 * @param buf statfs struct to fill
 * @return 0 on success, negative error codes (in our case, always succesful)
 */
int ext4_superblock::stat_fs(struct statfs *buf)
{
    buf->f_type = EXT4_SIGNATURE;
    buf->f_bsize = block_size;
    buf->f_blocks = sb->s_blocks_count;
    buf->f_bfree = sb->s_free_blocks_count;
    buf->f_bavail = sb->s_free_blocks_count - sb->s_r_blocks_count;
    buf->f_files = sb->s_inodes_count;
    buf->f_ffree = sb->s_free_inodes_count;

    return 0;
}

/**
   Calculates the checksum of the given buffer.
   @param[in]      sb             Pointer to the ext4 superblock.
   @param[in]      buffer         Pointer to the buffer.
   @param[in]      length         Length of the buffer, in bytes.
   @param[in]      initial_value  Initial value of the checksum.
   @return The checksum.
**/
uint32_t ext4_calculate_csum(const ext4_superblock *sb, const void *buffer, size_t length,
                             uint32_t initial_value)
{
    if (!EXT4_HAS_METADATA_CSUM(sb))
    {
        return 0;
    }

    switch (sb->sb->s_checksum_type)
    {
        case EXT4_CHECKSUM_CRC32C:
            // For some reason, EXT4 really likes non-inverted CRC32C checksums, so we stick to that
            // here.
            return ~crc32c_calculate(buffer, length, ~initial_value);
        default:
            panic("ext4: Bad checksum type %u - this should be unreachable\n",
                  sb->sb->s_checksum_type);
            return 0;
    }
}
