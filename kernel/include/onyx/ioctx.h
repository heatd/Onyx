/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _IOCTX_H
#define _IOCTX_H

#include <onyx/file.h>
#include <onyx/mutex.h>
#include <onyx/path.h>
#include <onyx/rcupdate.h>
#include <onyx/ref.h>
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
    refcount_t refs;
    /* Current working directory */
    struct spinlock fdlock;
    struct fd_table __rcu *table;
};

struct fsctx
{
    refcount_t refs;
    struct spinlock cwd_lock;
    struct path root;
    struct path cwd;
    mode_t umask;
};

static inline void fsctx_init(struct fsctx *fs)
{
    fs->refs = REFCOUNT_INIT(1);
    spinlock_init(&fs->cwd_lock);
    path_init(&fs->root);
    path_init(&fs->cwd);
    fs->umask = 0;
}

#endif
