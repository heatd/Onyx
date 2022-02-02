/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_PARTITIONS_H
#define _ONYX_PARTITIONS_H

#include <stdint.h>

#include <onyx/block.h>
#include <onyx/culstring.h>
#include <onyx/list.h>
#include <onyx/vfs.h>

typedef inode *(*fs_sb_mount)(blockdev *dev);

#define FS_MOUNT_PSEUDO_FS \
    (1 << 0) // Does not require a valid block device (->mount() is passed nullptr)

struct fs_mount
{
    list_head list_node;
    cul::string name;
    unsigned int flags;
    fs_sb_mount mount;
};

/**
 * @brief Add a fs mount object to the kernel's registry
 * After this call, mount(2) can try and mount these types of filesystems
 *
 * @param handler Callback to the mount handler
 * @param flags Flags (see FS_MOUNT_*)
 * @param name Name of the filesystem, passed by mount(2)
 * @return 0 on success, else negative error codes
 */
int fs_mount_add(fs_sb_mount handler, unsigned int flags, cul::string name);

/**
 * @brief Find the fs_mount from the name
 *
 * @param fsname Name of the filesystem, passed by mount(2)
 * @return Pointer to the fs_mount, or NULL
 */
fs_mount *fs_mount_get(const char *fsname);

#endif
