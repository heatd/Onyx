/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_PARTITIONS_H
#define _ONYX_PARTITIONS_H

#include <stdint.h>

#include <onyx/err.h>
#include <onyx/list.h>
#include <onyx/vfs.h>

struct blockdev;

struct vfs_mount_info
{
    struct blockdev *bdev;
    struct dentry *root_dir;
    unsigned long mnt_flags;
};

typedef struct superblock *(*fs_sb_mount)(struct vfs_mount_info *info);

#define FS_MOUNT_MAX_NAME 32

// Does not require a valid block device (->mount() is passed a NULL bdev)
#define FS_MOUNT_PSEUDO_FS (1 << 0)

struct fs_mount
{
    struct list_head list_node;
    char name[FS_MOUNT_MAX_NAME];
    unsigned int flags;
    fs_sb_mount mount;
};

__BEGIN_CDECLS

/**
 * @brief Add a fs mount object to the kernel's registry
 * After this call, mount(2) can try and mount these types of filesystems
 *
 * @param handler Callback to the mount handler
 * @param flags Flags (see FS_MOUNT_*)
 * @param name Name of the filesystem, passed by mount(2)
 * @return 0 on success, else negative error codes
 */
int fs_mount_add(fs_sb_mount handler, unsigned int flags, const char *name);

/**
 * @brief Find the fs_mount from the name
 *
 * @param fsname Name of the filesystem, passed by mount(2)
 * @return Pointer to the fs_mount, or NULL
 */
struct fs_mount *fs_mount_get(const char *fsname);

__END_CDECLS

#endif
