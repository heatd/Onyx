/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_TMPFS_H
#define _ONYX_TMPFS_H

#include <onyx/list.h>
#include <onyx/mutex.h>
#include <onyx/superblock.h>
#include <onyx/types.h>
#include <onyx/vfs.h>

#include <onyx/atomic.hpp>

struct tmpfs_inode : public inode
{
    /* Used to store the symlink, if it is one */
    const char *link;
};

extern const file_ops tmpfs_fops;

extern const super_ops tmpfs_sb_ops;

class tmpfs_superblock : public superblock
{
private:
    atomic<ino_t> curr_inode;

public:
    static atomic<dev_t> curr_minor_number;

    dev_t fs_minor;

    const file_ops *tmpfs_ops_;
    atomic<size_t> nblocks;
    atomic<size_t> ino_nr;

    tmpfs_superblock(unsigned int sb_flags)
        : superblock{}, curr_inode{}, fs_minor{++curr_minor_number}, tmpfs_ops_{&tmpfs_fops}
    {
        superblock_init(this, sb_flags);
        s_block_size = PAGE_SIZE;
        s_flags = SB_FLAG_NODIRTY | SB_FLAG_IN_MEMORY;
        this->s_ops = &tmpfs_sb_ops;
    }

    tmpfs_inode *create_inode(mode_t mode, dev_t rdev = 0);

    /**
     * @brief Allocate a tmpfs inode
     * Note: unlike create_inode, this function does not add an inode to the cache, set nlink to 1,
     * etc.
     *
     * @param mode Inode's mode
     * @param rdev rdev
     * @return The created tmpfs_inode, or NULL
     */
    tmpfs_inode *alloc_inode(mode_t mode, dev_t rdev);

    /**
     * @brief Set the file_ops for all the inodes of this filesystem
     *
     * @param ops Pointer to file_ops
     */
    void override_file_ops(file_ops *ops)
    {
        tmpfs_ops_ = ops;
    }
};

/**
 * @brief Tmpfs mount kernel helper function
 *
 * @param mountpoint Path where to mount the new tmpfs instance
 * @return 0 on success, else negative error codes
 */
int tmpfs_kern_mount(const char *mountpoint);

#endif
