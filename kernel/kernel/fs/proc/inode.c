/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/file.h>
#include <onyx/inode.h>
#include <onyx/mm/slab.h>
#include <onyx/page.h>
#include <onyx/proc.h>

static const struct inode_operations procfs_ino_ops = {
    .stat = proc_stat,
};

static int proc_on_open(struct file *filp)
{
    struct procfs_entry *entry = F_PROC_ENTRY(filp);
    if (entry->ops->open)
        return entry->ops->open(filp);
    return 0;
}

static void proc_release(struct file *filp)
{
    struct procfs_entry *entry = F_PROC_ENTRY(filp);
    if (entry->ops->release)
        entry->ops->release(filp);
}

ssize_t proc_read_iter(struct file *filp, size_t offset, struct iovec_iter *iter,
                       unsigned int flags)
{
    struct procfs_entry *entry = F_PROC_ENTRY(filp);
    if (entry->ops->read_iter)
        return entry->ops->read_iter(filp, offset, iter, flags);
    return -EIO;
}

ssize_t proc_write_iter(struct file *filp, size_t offset, struct iovec_iter *iter,
                        unsigned int flags)
{
    struct procfs_entry *entry = F_PROC_ENTRY(filp);
    if (entry->ops->write_iter)
        return entry->ops->write_iter(filp, offset, iter, flags);
    return -EIO;
}

static const struct file_ops procfs_file_ops = {
    .on_open = proc_on_open,
    .read_iter = proc_read_iter,
    .write_iter = proc_write_iter,
    .release = proc_release,
};

struct inode *proc_create_inode(struct superblock *sb, struct procfs_entry *entry)
{
    struct inode *inode = kmalloc(sizeof(*inode), GFP_KERNEL);
    if (!inode)
        return NULL;
    if (inode_init(inode, false) < 0)
        goto err;

    inode->i_mode = entry->mode;
    if ((entry->mode & S_IFMT) == 0)
        inode->i_mode |= S_IFREG;
    inode->i_uid = entry->uid;
    inode->i_gid = entry->gid;
    inode->i_sb = sb;
    inode->i_op = entry->iops ?: &procfs_ino_ops;
    inode->i_fops = (struct file_ops *) (entry->fops ?: &procfs_file_ops);
    inode->i_size = entry->size;
    inode->i_inode = entry->inum;
    inode->i_helper = entry;
    inode->i_mtime = inode->i_ctime = inode->i_atime = clock_get_posix_time();

    return inode;

err:
    kfree(inode);
    return NULL;
}
