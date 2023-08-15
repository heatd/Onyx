/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _IOCTX_H
#define _IOCTX_H

#include <onyx/file.h>
#include <onyx/mutex.h>
#include <onyx/rcupdate.h>
#include <onyx/types.h>
#include <onyx/vfs.h>

#define FDS_PER_LONG            (sizeof(unsigned long) * 8)
#define FILE_DESCRIPTOR_GROW_NR (FDS_PER_LONG)

struct fd_table
{
    struct file **file_desc;
    unsigned int file_desc_entries;
    unsigned long *cloexec_fds;
    unsigned long *open_fds;
    struct rcu_head rcuhead;
};

struct ioctx
{
    /* Current working directory */
    spinlock cwd_lock{};
    file *cwd{};
    spinlock fdlock{};
    fd_table __rcu *table{};
    mode_t umask{};
};

#endif
