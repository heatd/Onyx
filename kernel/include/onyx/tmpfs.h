/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_TMPFS_H
#define _ONYX_TMPFS_H

#include <sys/types.h>

#include <onyx/list.h>
#include <onyx/mutex.h>
#include <onyx/superblock.h>
#include <onyx/vfs.h>

#include <onyx/atomic.hpp>

struct tmpfs_inode : public inode
{
    /* Used to store the symlink, if it is one */
    const char *link;
};

extern file_ops tmpfs_fops;

class tmpfs_superblock : public superblock
{
private:
    atomic<ino_t> curr_inode;

public:
    static atomic<dev_t> curr_minor_number;

    dev_t fs_minor;

    list_head_cpp<tmpfs_superblock> fs_list_node;

    file_ops *tmpfs_ops_;

    tmpfs_superblock()
        : superblock{}, curr_inode{}, fs_minor{++curr_minor_number}, fs_list_node{this},
          tmpfs_ops_{&tmpfs_fops}
    {
        s_block_size = PAGE_SIZE;
    }

    tmpfs_inode *create_inode(mode_t mode, dev_t rdev = 0);

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
