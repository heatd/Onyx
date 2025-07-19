/*
 * Copyright (c) 2024 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define DEFINE_CURRENT
#include <ctype.h>

#include <onyx/fs_mount.h>
#include <onyx/libfs.h>
#include <onyx/mm/slab.h>
#include <onyx/proc.h>
#include <onyx/process.h>
#include <onyx/rculist.h>
#include <onyx/rcupdate.h>
#include <onyx/seq_file.h>
#include <onyx/seqlock.h>
#include <onyx/superblock.h>
#include <onyx/tty.h>

int proc_open_entry(struct dentry *dir, const char *name, struct dentry *dentry)
{
    struct procfs_entry *entry = I_PROC_ENTRY(dir->d_inode);
    struct procfs_entry *found;
    struct inode *inode;

    spin_lock(&entry->children_lock);
    list_for_each_entry (found, &entry->children, child_node)
    {
        if (!strcmp(name, found->name))
            goto positive;
    }

    spin_unlock(&entry->children_lock);
    return -ENOENT;
positive:
    /* TODO: Reference counting */
    spin_unlock(&entry->children_lock);
    inode = proc_create_inode(dir->d_inode->i_sb, found);
    if (!inode)
        return -ENOMEM;
    d_finish_lookup(dentry, inode);
    return 0;
}

int proc_pid_open(struct dentry *dir, const char *name, struct dentry *dentry);

static int proc_root_open(struct dentry *dir, const char *name, struct dentry *dentry)
{
    int err = proc_pid_open(dir, name, dentry);
    if (err != -EINVAL)
        return err;
    return proc_open_entry(dir, name, dentry);
}

/* TODO: PID_MAX */
#define PROC_ROOT_PID_END (1U << 22)

static off_t proc_root_pid_getdirent(struct dirent *buf, off_t off, struct procfs_entry *dir,
                                     struct file *file)
{
    struct process *task;
    char name[32];
    off_t ret = PROC_ROOT_PID_END + 2;
    rcu_read_lock();

    list_for_each_entry_rcu (task, &tasklist, tasklist_node)
    {
        if (!thread_group_leader(task))
            continue;
        if (task->pid_ < off)
            continue;

        sprintf(name, "%d", task->pid_);
        put_dir(name, task->pid_, 0, DT_DIR, buf);
        ret = task->pid_ + 1;
        break;
    }

    rcu_read_unlock();
    return ret;
}

static off_t proc_root_getdirent(struct dirent *buf, off_t off, struct file *file)
{
    off_t i;
    struct procfs_entry *dir = I_PROC_ENTRY(file->f_dentry->d_inode), *entry;
    if (off < PROC_ROOT_PID_END)
    {
        i = proc_root_pid_getdirent(buf, off, dir, file);
        if (i != PROC_ROOT_PID_END + 2)
            return i;
        off = PROC_ROOT_PID_END;
    }

    if (off - PROC_ROOT_PID_END < 2)
        return libfs_put_dots(buf, off - PROC_ROOT_PID_END, file->f_dentry) + PROC_ROOT_PID_END;

    i = off - PROC_ROOT_PID_END - 2;
    spin_lock(&dir->children_lock);

    list_for_each_entry (entry, &dir->children, child_node)
    {
        if (i > 0)
        {
            i--;
            continue;
        }

        put_dir(entry->name, off, entry->inum, IFTODT(entry->mode), buf);
        spin_unlock(&dir->children_lock);
        return off + 1;
    }

    spin_unlock(&dir->children_lock);
    return 0;
}

int proc_stat(struct stat *buf, const struct path *path)
{
    default_stat(buf, path);
    buf->st_nlink = I_PROC_ENTRY(path->dentry->d_inode)->nlink;
    return 0;
}

static const struct inode_operations proc_root_ino_ops = {
    .open = proc_root_open,
    .link = libfs_no_link,
    .unlink = libfs_no_unlink,
    .readlink = libfs_no_readlink,
    .stat = proc_stat,
};

static const struct file_ops proc_root_file_ops = {
    .getdirent = proc_root_getdirent,
    .symlink = libfs_no_symlink,
};

struct procfs_entry root_entry = {
    .name = "",
    .mode = S_IFDIR | 0777,
    .nlink = 2,
    .uid = 0,
    .gid = 0,
    .children = LIST_HEAD_INIT(root_entry.children),
    .children_lock = __SPIN_LOCK_UNLOCKED(root_entry.children_lock),
    .inum = 2,
    .iops = &proc_root_ino_ops,
    .fops = &proc_root_file_ops,
};

static void proc_evict_inode(struct inode *ino)
{
    struct procfs_inode *inode = (struct procfs_inode *) ino;
    if (inode->owner)
        put_pid(inode->owner);
}

static const struct super_ops proc_sb_ops = {
    .evict_inode = proc_evict_inode,
    .shutdown = sb_generic_shutdown,
};

static struct superblock *proc_mount(struct vfs_mount_info *info)
{
    struct inode *root_ino;
    struct superblock *sb = kmalloc(sizeof(*sb), GFP_KERNEL);
    if (!sb)
        return NULL;
    superblock_init(sb);

    root_ino = proc_create_inode(sb, &root_entry);
    if (!root_ino)
    {
        sb_shutdown(sb);
        return NULL;
    }

    sb->s_flags |= SB_FLAG_NODIRTY;
    sb->s_ops = &proc_sb_ops;
    d_positiveize(info->root_dir, root_ino);
    return sb;
}

__init static void procfs_init(void)
{
    CHECK(fs_mount_add(proc_mount, FS_MOUNT_PSEUDO_FS, "proc") == 0);
}

/* TODO: Do this better? */
static ino_t inum = 3;

void procfs_init_entry(struct procfs_entry *entry, const char *name, mode_t mode,
                       struct procfs_entry *parent, const struct proc_file_ops *ops)
{
    memset(entry, 0, sizeof(*entry));
    INIT_LIST_HEAD(&entry->children);
    spin_lock_init(&entry->children_lock);
    entry->inum = __atomic_fetch_add(&inum, 1, __ATOMIC_RELAXED);
    entry->ops = ops;
    entry->mode = mode;
    entry->name = name;
    if (S_ISDIR(entry->mode))
        entry->nlink = 2;
    else
        entry->nlink = 1;
}

struct procfs_entry *procfs_add_entry(const char *name, mode_t mode, struct procfs_entry *parent,
                                      const struct proc_file_ops *ops)
{
    struct procfs_entry *new;
    if (!parent)
        parent = &root_entry;

    new = kmalloc(sizeof(*new), GFP_KERNEL);
    if (!new)
        return NULL;
    procfs_init_entry(new, name, mode, parent, ops);

    spin_lock(&parent->children_lock);
    list_add_tail(&new->child_node, &parent->children);
    spin_unlock(&parent->children_lock);
    return new;
}

const struct proc_file_ops proc_noop;

static char *procfs_self_readlink(struct dentry *dentry)
{
    char *link = kmalloc(16, GFP_KERNEL);
    if (!link)
        return ERR_PTR(-ENOMEM);
    sprintf(link, "%d", pid_nr(current->sig->tgid));
    return link;
}

static const struct proc_file_ops proc_self_ops = {
    .readlink = procfs_self_readlink,
};

static char *procfs_threadself_readlink(struct dentry *dentry)
{
    char *link = kmalloc(16, GFP_KERNEL);
    if (!link)
        return ERR_PTR(-ENOMEM);
    sprintf(link, "%d", current->pid_);
    return link;
}

static const struct proc_file_ops proc_threadself_ops = {
    .readlink = procfs_threadself_readlink,
};

static __init void procfs_self_init(void)
{
    procfs_add_entry("self", S_IFLNK | 0777, NULL, &proc_self_ops);
    procfs_add_entry("thread-self", S_IFLNK | 0777, NULL, &proc_threadself_ops);
}

int str_to_int(const char *name)
{
    unsigned int pid = 0, old;
    while (*name)
    {
        char c = *name;
        if (!isdigit(c))
            return -1;
        old = pid;
        pid *= 10;
        pid += c - '0';
        if (old > pid)
            return -1;
        name++;
    }

    if (pid > INT_MAX)
        return -1;
    return pid;
}
