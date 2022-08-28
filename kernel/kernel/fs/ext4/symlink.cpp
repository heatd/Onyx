/*
 * Copyright (c) 2017 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <onyx/pagecache.h>
#include <onyx/vfs.h>

#include "ext4.h"

/**
 * @brief Detects if a symlink is a fast symlink
 *
 * @param inode Pointer to ext4_inode struct
 * @param fs Pointer to ext4_superblock struct
 * @return True if a fast symlink, else false.
 */
bool ext4_is_fast_symlink(struct ext4_inode *inode, struct ext4_superblock *fs)
{
    /* Essentially, we're comparing the extended attribute blocks
     * with the inode's i_blocks, and if it's zero we know the inode isn't storing
     * the link in filesystem blocks, so we look to the ext4_inode->i_data.
     */

    int ea_blocks = inode->i_file_acl ? (fs->block_size >> 9) : 0;
    return (inode->i_blocks - ea_blocks == 0 && EXT4_CALCULATE_SIZE64(inode) <= 60);
}

#define EXT4_FAST_SYMLINK_SIZE 60

char *ext4_do_fast_symlink(struct ext4_inode *inode)
{
    /* Fast symlinks have 60 bytes and we allocate one more for the null byte */
    char *buf = (char *) malloc(EXT4_FAST_SYMLINK_SIZE + 1);
    if (!buf)
        return NULL;
    memcpy(buf, &inode->i_data, EXT4_FAST_SYMLINK_SIZE);
    buf[EXT4_FAST_SYMLINK_SIZE] = '\0';
    /* TODO: Is it possible to trim this string? And should we? */
    return buf;
}

char *ext4_do_slow_symlink(struct inode *inode)
{
    size_t len = inode->i_size;
    char *buf = (char *) malloc(len + 1);
    if (!buf)
        return NULL;

    unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

    ssize_t read = file_read_cache(buf, len, inode, 0);

    thread_change_addr_limit(old);

    if (read != (ssize_t) len)
    {
        free(buf);
        return NULL;
    }

    buf[len] = '\0';

    return buf;
}

char *ext4_read_symlink(struct inode *ino, struct ext4_superblock *fs)
{
    auto raw = ext4_get_inode_from_node(ino);

    if (ext4_is_fast_symlink(raw, fs))
    {
        return ext4_do_fast_symlink(raw);
    }
    else
    {
        return ext4_do_slow_symlink(ino);
    }
}

char *ext4_readlink(struct file *f)
{
    struct ext4_superblock *fs = ext4_superblock_from_inode(f->f_ino);

    return ext4_read_symlink(f->f_ino, fs);
}

int ext4_set_symlink(inode *ino, const char *dest)
{
    auto length = strlen(dest);
    auto raw_ino = ext4_get_inode_from_node(ino);

    if (length <= 60)
    {
        memcpy(&raw_ino->i_data, dest, length);
    }
    else
    {
        unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

        // TODO: Kind of dumb that it's not a const void *, fix?
        ssize_t read = file_write_cache((void *) dest, length, ino, 0);

        thread_change_addr_limit(old);

        if (read != (ssize_t) length)
        {
            return -errno;
        }
    }

    ext4_set_inode_size(raw_ino, length);

    inode_mark_dirty(ino);

    return 0;
}

inode *ext4_symlink(const char *name, const char *dest, dentry *dir)
{
    auto inode = ext4_create_file(name, S_IFLNK | S_IRWXG | S_IRWXO | S_IRWXU, 0, dir);
    if (!inode)
        return nullptr;

    if (auto st = ext4_set_symlink(inode, dest); st < 0)
    {
        ext4_unlink(name, 0, dir);
        delete inode;
        errno = -st;
        return nullptr;
    }

    return inode;
}
