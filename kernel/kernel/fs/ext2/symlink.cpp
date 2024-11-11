/*
 * Copyright (c) 2017 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <onyx/cred.h>
#include <onyx/pagecache.h>
#include <onyx/vfs.h>

#include <uapi/fcntl.h>

#include "ext2.h"

/**
 * @brief Detects if a symlink is a fast symlink
 *
 * @param inode Pointer to ext2_inode struct
 * @param fs Pointer to ext2_superblock struct
 * @return True if a fast symlink, else false.
 */
bool ext2_is_fast_symlink(struct inode *inode, struct ext2_inode *e2inode,
                          struct ext2_superblock *fs)
{
    /* Essentially, we're comparing the extended attribute blocks
     * with the inode's i_blocks, and if it's zero we know the inode isn't storing
     * the link in filesystem blocks, so we look to the ext2_inode->i_data.
     */

    int ea_blocks = e2inode->i_file_acl ? (fs->block_size >> 9) : 0;
    return (inode->i_blocks - ea_blocks == 0 && inode->i_size <= 60);
}

#define EXT2_FAST_SYMLINK_SIZE 60

char *ext2_do_fast_symlink(struct ext2_inode *inode)
{
    /* Fast symlinks have 60 bytes and we allocate one more for the null byte */
    char *buf = (char *) malloc(EXT2_FAST_SYMLINK_SIZE + 1);
    if (!buf)
        return NULL;
    memcpy(buf, &inode->i_data, EXT2_FAST_SYMLINK_SIZE);
    buf[EXT2_FAST_SYMLINK_SIZE] = '\0';
    /* TODO: Is it possible to trim this string? And should we? */
    return buf;
}

char *ext2_do_slow_symlink(struct inode *inode)
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

char *ext2_read_symlink(struct inode *ino, struct ext2_superblock *fs)
{
    auto raw = ext2_get_inode_from_node(ino);

    if (ext2_is_fast_symlink(ino, raw, fs))
        return ext2_do_fast_symlink(raw);
    else
        return ext2_do_slow_symlink(ino);
}

char *ext2_readlink(struct file *f)
{
    struct ext2_superblock *fs = ext2_superblock_from_inode(f->f_ino);

    return ext2_read_symlink(f->f_ino, fs);
}

int ext2_set_symlink(inode *ino, const char *dest)
{
    auto length = strlen(dest) + 1;
    auto raw_ino = ext2_get_inode_from_node(ino);
    struct ext2_superblock *fs = ext2_superblock_from_inode(ino);
    if (length > fs->block_size)
        return -ENAMETOOLONG;

    if (length <= 60)
    {
        memcpy(&raw_ino->i_data, dest, length);
        ino->i_size = length - 1;
    }
    else
    {
        unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

        // TODO: Kind of dumb that it's not a const void *, fix?
        ssize_t read = file_write_cache((void *) dest, length - 1, ino, 0);

        thread_change_addr_limit(old);

        if (read != (ssize_t) length - 1)
            return -errno;
    }

    inode_mark_dirty(ino);

    return 0;
}

inode *ext2_symlink(struct dentry *dentry, const char *dest, struct dentry *dir)
{
    struct inode *vfs_ino = dir->d_inode;
    struct ext2_superblock *fs = ext2_superblock_from_inode(vfs_ino);
    uint32_t inumber = 0;
    struct inode *ino = nullptr;
    unsigned long old = 0;
    struct creds *c = nullptr;

    if (WARN_ON(dentry->d_name_length == 0))
        return errno = EIO, nullptr;

    auto res = fs->allocate_inode();
    if (res.has_error())
    {
        errno = -res.error();
        return nullptr;
    }

    auto p = res.value();
    inumber = p.first;

    struct ext2_inode *inode = p.second;
    struct ext2_inode *dir_inode = ext2_get_inode_from_node(vfs_ino);

    if (!inode)
        return nullptr;

    memset(inode, 0, sizeof(struct ext2_inode));
    inode->i_ctime = inode->i_atime = inode->i_mtime = (uint32_t) clock_get_posix_time();

    c = creds_get();

    inode->i_uid = c->euid;
    inode->i_gid = c->egid;

    creds_put(c);
    inode->i_mode = EXT2_INO_TYPE_SYMLINK | (S_IRWXG | S_IRWXO | S_IRWXU);

    ino = ext2_fs_ino_to_vfs_ino(inode, inumber, fs);
    if (!ino)
    {
        errno = ENOMEM;
        goto free_ino_error;
    }

    fs->update_inode(inode, inumber);
    fs->update_inode(dir_inode, vfs_ino->i_inode);

    old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

    if (auto st = ext2_set_symlink(ino, dest); st < 0)
    {
        errno = -st;
        goto free_ino_error;
    }

    if (int st = ext2_add_direntry(dentry->d_name, inumber, inode, vfs_ino, fs); st < 0)
    {
        thread_change_addr_limit(old);
        errno = -st;
        goto free_ino_error;
    }

    inode_inc_nlink(ino);

    thread_change_addr_limit(old);
    superblock_add_inode(vfs_ino->i_sb, ino);
    return ino;

free_ino_error:
    inode_unref(ino);
    return nullptr;
}
