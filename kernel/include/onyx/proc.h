/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_PROCFS_H
#define _ONYX_PROCFS_H

#include <onyx/inode.h>

__BEGIN_CDECLS

struct procfs_inode
{
    struct inode pfi_inode;
    struct pid *owner;
};

struct proc_file_ops
{
    int (*open)(struct file *filp);
    void (*release)(struct file *filp);
    ssize_t (*read_iter)(struct file *filp, size_t offset, struct iovec_iter *iter,
                         unsigned int flags);
    ssize_t (*write_iter)(struct file *filp, size_t offset, struct iovec_iter *iter,
                          unsigned int flags);
    char *(*readlink)(struct file *filp);
};

struct inode_operations;

struct procfs_entry
{
    const char *name;
    size_t size;
    mode_t mode;
    nlink_t nlink;
    uid_t uid;
    gid_t gid;
    struct spinlock children_lock;
    struct list_head children;
    struct list_head child_node;
    const struct proc_file_ops *ops;
    /* May be null, if so, default operations apply */
    const struct inode_operations *iops;
    const struct file_ops *fops;
    const struct dentry_operations *dops;
    ino_t inum;
};

struct procfs_entry *procfs_add_entry(const char *name, mode_t mode, struct procfs_entry *parent,
                                      const struct proc_file_ops *ops);

struct inode *proc_create_inode(struct superblock *sb, struct procfs_entry *entry);

#define I_PROC_ENTRY(inode) ((struct procfs_entry *) (inode)->i_helper)
#define F_PROC_ENTRY(filp)  (I_PROC_ENTRY((filp)->f_dentry->d_inode))
int proc_stat(struct stat *buf, const struct path *path);

struct process *get_inode_task(struct procfs_inode *ino);
__END_CDECLS

#endif
