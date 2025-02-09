/*
 * Copyright (c) 2024 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_VFORK_COMPLETION_H
#define _ONYX_VFORK_COMPLETION_H

#include <onyx/atomic.h>
#include <onyx/cpu.h>
#include <onyx/wait_queue.h>

struct vfork_completion
{
    struct wait_queue wq;
    bool done;
    bool may_exit;
};

static inline void vfork_compl_init(struct vfork_completion* c)
{
    init_wait_queue_head(&c->wq);
    c->done = false;
    c->may_exit = false;
}

static inline int vfork_compl_wait(struct vfork_completion* c)
{
    return wait_for_event(&c->wq, READ_ONCE(c->done));
}

static inline void vfork_compl_wake(struct vfork_completion* c)
{
    WRITE_ONCE(c->done, true);
    wait_queue_wake_all(&c->wq);
    /* Pairs with smp_rmb in vfork_compl_wait_to_exit. Previous stores and loads are required to
     * happen before may_exit is stored. */
    smp_mb();
    WRITE_ONCE(c->may_exit, true);
}

static inline void vfork_compl_wait_to_exit(struct vfork_completion* c)
{
    while (!READ_ONCE(c->may_exit))
        cpu_relax();
    /* Pairs with smp_mb in vfork_compl_wake */
    smp_rmb();
}

#endif
