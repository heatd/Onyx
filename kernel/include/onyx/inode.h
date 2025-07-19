/*
 * Copyright (c) 2016 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_INODE_H
#define _ONYX_INODE_H

#include <onyx/flock.h>
#include <onyx/list.h>
#include <onyx/rwlock.h>
#include <onyx/types.h>

#include <uapi/stat.h>

struct inode;
struct dentry;
struct dirent;
struct file;
struct iovec_iter;
struct readpages_state;
struct page;
struct vm_area_struct;
struct path;

typedef size_t (*__read)(size_t offset, size_t sizeofread, void *buffer, struct file *file);
typedef size_t (*__write)(size_t offset, size_t sizeofwrite, void *buffer, struct file *file);
typedef void (*__close)(struct inode *file);
typedef int (*__open)(struct dentry *dir, const char *name, struct dentry *dentry);
typedef off_t (*__getdirent)(struct dirent *buf, off_t off, struct file *file);
typedef unsigned int (*__ioctl)(int request, void *argp, struct file *file);
typedef struct inode *(*__creat)(struct dentry *dentry, int mode, struct dentry *dir);
typedef int (*__stat)(struct stat *buf, const struct path *path);
typedef struct inode *(*__symlink)(struct dentry *dentry, const char *linkpath, struct dentry *dir);
typedef unsigned int (*putdir_t)(struct dirent *, struct dirent *ubuf, unsigned int count);

struct writepages_info
{
    /* Start and end (inclusive) of writepages */
    unsigned long start;
    unsigned long end;
    unsigned int flags;
};

/* Wait for writeback to complete (this is part of sync or fsync) */
#define WRITEPAGES_SYNC (1 << 0)

struct file_ops
{
    __read read;
    __write write;
    __close close;
    __getdirent getdirent;
    __ioctl ioctl;
    __symlink symlink;
    void *(*mmap)(struct vm_area_struct *area, struct file *node);
    int (*on_open)(struct file *node);
    short (*poll)(void *poll_file, short events, struct file *node);
    int (*fallocate)(int mode, off_t offset, off_t len, struct file *node);
    int (*fcntl)(struct file *filp, int cmd, unsigned long arg);
    void (*release)(struct file *filp);
    ssize_t (*read_iter)(struct file *filp, size_t offset, struct iovec_iter *iter,
                         unsigned int flags);
    ssize_t (*write_iter)(struct file *filp, size_t offset, struct iovec_iter *iter,
                          unsigned int flags);
    int (*fsyncdata)(struct inode *ino, struct writepages_info *wpinfo);
    ssize_t (*directio)(struct file *file, size_t off, struct iovec_iter *iter, unsigned int flags);
};

struct nameidata;

struct inode_operations
{
    __open open;
    __stat stat;
    __creat creat;
    int (*rename)(struct dentry *src_parent, struct dentry *src, struct dentry *dst_dir,
                  struct dentry *dst);
    int (*link)(struct dentry *old_dentry, struct dentry *new_dentry);
    int (*ftruncate)(size_t length, struct file *node);
    struct inode *(*mkdir)(struct dentry *dentry, mode_t mode, struct dentry *dir);
    struct inode *(*mknod)(struct dentry *dentry, mode_t mode, dev_t dev, struct dentry *dir);
    char *(*readlink)(struct dentry *dentry);
    int (*unlink)(const char *name, int flags, struct dentry *dir);
    int (*magic_jump)(struct dentry *dentry, struct inode *inode, struct nameidata *data);
};

/* For directio's flags */
#define DIRECT_IO_OP(op) ((op) << 0)

enum
{
    DIRECT_IO_READ = 0,
    DIRECT_IO_WRITE,
};

struct getdents_ret
{
    int read;
    off_t new_off;
};

__BEGIN_CDECLS
int inode_init(struct inode *ino, bool is_reg);
void namei_jump(struct nameidata *data, struct path *path);
__END_CDECLS

struct pipe;

#define INODE_FLAG_DONT_CACHE (1 << 0)
#define INODE_FLAG_NO_SEEK    (1 << 2)
#define I_FREEING             (1 << 4)
#define I_DATADIRTY           (1 << 5)
#define I_DIRTY               (1 << 1)
#define I_WRITEBACK           (1 << 3)
#define I_HASHED              (1 << 7)

#define I_DIRTYALL (I_DIRTY | I_DATADIRTY)

struct inode
{
    /* Read-only/mostly fields */
    ino_t i_inode;
    gid_t i_gid;
    uid_t i_uid;
    mode_t i_mode;
    dev_t i_dev;
    dev_t i_rdev;
    struct superblock *i_sb;
    const struct inode_operations *i_op;
    struct file_ops *i_fops;
    struct vm_object *i_pages;
    void *i_helper;
    struct dentry *i_dentry; /* Only valid for directories */
    // For FIFOs
    struct pipe *i_pipe;
    size_t i_size;
    nlink_t i_nlink;
    blkcnt_t i_blocks;
    struct list_head i_sb_list_node;
    struct flock_info *i_flock;

    /* Write-frequently fields */
    unsigned long i_refc;
    unsigned int i_flags;
    time_t i_atime;
    time_t i_ctime;
    time_t i_mtime;
    struct list_head i_dirty_inode_node;
    void *i_flush_dev;

    struct rwlock i_rwlock;
    struct list_head i_hash_list_node;
    struct spinlock i_lock;

#ifdef __cplusplus
    int init(mode_t mode)
    {
        return inode_init(this, S_ISREG(mode));
    }

    void set_evicting();
#endif
};

static inline struct flock_info *inode_to_flock(struct inode *inode)
{
    /* We not need an acquire load here for the same reason rcu_dereference doesn't - dependent
     * stores. */
    return READ_ONCE(inode->i_flock);
}

#endif
