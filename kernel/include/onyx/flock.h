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

#include <uapi/flock.h>

/* BSD flock(2) and POSIX advisory locks implementation information */

struct file;

struct flock_info
{
    struct wait_queue flock_wq;
    struct list_head shared_holders;
    struct list_head excl_holders;
    struct list_head posix_locks;
    struct spinlock lock;
};

struct flock_file_info
{
    struct list_head list_node;
    int type;
};

struct flock_posix_lock
{
    off_t start;
    off_t end;
    union {
        pid_t pid;
        struct file *filp;
    } owner;

    unsigned int flags;
    struct list_head list_node;
};

#define FLOCK_POSIX_WR    (1 << 0)
#define FLOCK_POSIX_UNLCK (1 << 1)
#define FLOCK_POSIX_OFD   (1 << 2)

__BEGIN_CDECLS

struct file;
void flock_release(struct file *filp);

static inline void flock_init(struct flock_info *flock)
{
    INIT_LIST_HEAD(&flock->shared_holders);
    INIT_LIST_HEAD(&flock->excl_holders);
    INIT_LIST_HEAD(&flock->posix_locks);
    init_wait_queue_head(&flock->flock_wq);
    spinlock_init(&flock->lock);
}

int flock_do_posix(struct file *filp, int cmd, struct flock *arg, bool has_seek);
void flock_remove_ofd(struct file *filp);
void flock_remove_posix(struct file *filp);

__END_CDECLS

#endif
