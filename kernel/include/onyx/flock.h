/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_FLOCK_H
#define _ONYX_FLOCK_H

#include <sys/file.h>

#include <onyx/compiler.h>
#include <onyx/list.h>
#include <onyx/wait_queue.h>

/* BSD flock(2) implementation information */

struct flock_info
{
    struct wait_queue flock_wq;
    struct list_head shared_holders;
    struct list_head excl_holders;
    struct spinlock lock;
};

struct flock_file_info
{
    struct list_head list_node;
    int type;
};

__BEGIN_CDECLS

struct file;
void flock_release(struct file *filp);

static inline void flock_init(struct flock_info *flock)
{
    INIT_LIST_HEAD(&flock->shared_holders);
    INIT_LIST_HEAD(&flock->excl_holders);
    init_wait_queue_head(&flock->flock_wq);
    spinlock_init(&flock->lock);
}

__END_CDECLS

#endif
