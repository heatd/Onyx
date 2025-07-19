/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_LIBFS_H
#define _ONYX_LIBFS_H

#include <errno.h>
#include <stdlib.h>

#include <onyx/compiler.h>
#include <onyx/types.h>
#include <onyx/vfs.h>

struct inode;
struct dentry;
struct file;
struct dirent;

__BEGIN_CDECLS

static inline int libfs_no_open(struct dentry *dir, const char *name, struct dentry *dentry)
{
    return -ENOENT;
}

static inline off_t libfs_no_getdirent(struct dirent *buf, off_t off, struct file *file)
{
    return -EIO;
}

static inline struct inode *libfs_no_creat(struct dentry *dentry, int mode, struct dentry *dir)
{
    errno = EROFS;
    return NULL;
}

static inline struct inode *libfs_no_symlink(struct dentry *dentry, const char *linkpath,
                                             struct dentry *dir)
{
    errno = EROFS;
    return NULL;
}

static inline struct inode *libfs_no_mkdir(struct dentry *dentry, mode_t mode, struct dentry *dir)
{
    errno = EROFS;
    return NULL;
}

static inline struct inode *libfs_no_mknod(struct dentry *dentry, mode_t mode, dev_t dev,
                                           struct dentry *dir)
{
    errno = EROFS;
    return NULL;
}

static inline int libfs_no_link(struct dentry *old_dentry, struct dentry *new_dentry)
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

static inline char *libfs_no_readlink(struct dentry *dentry)
{
    errno = EINVAL;
    return NULL;
}

static inline int libfs_no_unlink(const char *name, int flags, struct dentry *dir)
{
    return -EROFS;
}

off_t libfs_put_dots(struct dirent *buf, off_t off, struct dentry *dent);
void put_dir(const char *name, off_t off, ino_t ino, unsigned int dtype, struct dirent *buf);

int default_stat(struct stat *buf, const struct path *path);

__END_CDECLS

#endif
