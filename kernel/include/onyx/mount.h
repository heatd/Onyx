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

struct dentry;
struct superblock;

struct mount
{
    struct dentry *mnt_root;
    struct superblock *mnt_sb;
    struct dentry *mnt_point;
    unsigned int mnt_flags;
    /* TODO: percpu */
    unsigned long mnt_count;
    unsigned long mnt_writecount;
    struct rcu_head mnt_rcu;
    struct list_head mnt_mp_node;
    struct list_head mnt_node;
};

static inline void mnt_get(struct mount *mnt)
{
    __atomic_add_fetch(&mnt->mnt_count, 1, __ATOMIC_RELAXED);
}

__BEGIN_CDECLS

int do_mount(const char *source, const char *target, const char *fstype, unsigned long mnt_flags,
             const void *data);

struct dentry *mnt_traverse(struct dentry *mountpoint);

__END_CDECLS

#endif
