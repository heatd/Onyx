/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_MOUNT_H
#define _ONYX_MOUNT_H

#include <onyx/list.h>
#include <onyx/rcupdate.h>
#include <onyx/seqlock_types.h>

struct dentry;
struct superblock;

#define MNT_DOOMED (1U << 31)

struct mount
{
    struct dentry *mnt_root;
    struct superblock *mnt_sb;
    struct dentry *mnt_point;
    struct mount *mnt_parent;
    const char *mnt_devname;
    unsigned int mnt_flags;
    /* TODO: percpu */
    unsigned long mnt_count;
    unsigned long mnt_writecount;
    struct rcu_head mnt_rcu;
    struct list_head mnt_mp_node;
    struct list_head mnt_node;
    struct list_head mnt_submounts;
    struct list_head mnt_submount_node;
    struct list_head mnt_namespace_node;
};

static inline void mnt_get(struct mount *mnt)
{
    __atomic_add_fetch(&mnt->mnt_count, 1, __ATOMIC_RELAXED);
}

static inline void mnt_put(struct mount *mnt)
{
    __atomic_sub_fetch(&mnt->mnt_count, 1, __ATOMIC_RELAXED);
}

__BEGIN_CDECLS

int do_mount(const char *source, const char *target, const char *fstype, unsigned long mnt_flags,
             const void *data);

struct fs_mount;

struct mount *kern_mount(struct fs_mount *mount);

struct mount *mnt_traverse(struct dentry *mountpoint);

extern seqlock_t mount_lock;

__END_CDECLS

#endif
