/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_LIBFS_H
#define _ONYX_LIBFS_H

#include <errno.h>
#include <stdlib.h>

#include <onyx/types.h>

struct inode;
struct dentry;
struct file;
struct dirent;

static inline struct inode *libfs_no_open(struct dentry *dir, const char *name)
{
    errno = ENOENT;
    return NULL;
}

static inline off_t libfs_no_getdirent(struct dirent *buf, off_t off, struct file *file)
{
    return -EIO;
}

static inline struct inode *libfs_no_creat(const char *name, int mode, struct dentry *dir)
{
    errno = EROFS;
    return NULL;
}

static inline struct inode *libfs_no_symlink(const char *name, const char *linkpath,
                                             struct dentry *dir)
{
    errno = EROFS;
    return NULL;
}

static inline struct inode *libfs_no_mkdir(const char *name, mode_t mode, struct dentry *dir)
{
    errno = EROFS;
    return NULL;
}

static inline struct inode *libfs_no_mknod(const char *name, mode_t mode, dev_t dev,
                                           struct dentry *dir)
{
    errno = EROFS;
    return NULL;
}

static inline int libfs_no_link(struct file *target_ino, const char *name, struct dentry *dir)
{
    return -EROFS;
}

static inline int libfs_no_ftruncate(size_t length, struct file *node)
{
    return -EROFS;
}

static inline int libfs_no_fallocate(int mode, off_t offset, off_t len, struct file *node)
{
    return -EROFS;
}

static inline char *libfs_no_readlink(struct file *ino)
{
    errno = EINVAL;
    return NULL;
}

static inline int libfs_no_unlink(const char *name, int flags, struct dentry *dir)
{
    return -EROFS;
}

#endif
