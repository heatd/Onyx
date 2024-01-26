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

#ifdef __cplusplus
// clang-format off
#define CPP_DFLINIT {}
// clang-format on
#else
#define CPP_DFLINIT
#endif

struct ioctx
{
    /* Current working directory */
    struct spinlock cwd_lock CPP_DFLINIT;
    struct file *cwd CPP_DFLINIT;
    struct spinlock fdlock CPP_DFLINIT;
    struct fd_table __rcu *table CPP_DFLINIT;
    mode_t umask CPP_DFLINIT;
};

#endif
