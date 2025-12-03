/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_RCUWAIT_H
#define _ONYX_RCUWAIT_H

#include <onyx/rcuwait_types.h>
#include <onyx/scheduler.h>

#define __RCUWAIT_INITIALIZER(name) \
    {                               \
        .task = NULL,               \
    }

static inline void rcuwait_init(struct rcuwait *w)
{
    w->task = NULL;
}

void rcuwait_wake_up(struct rcuwait *wait);

static inline void prepare_to_rcuwait(struct rcuwait *wait)
{
    rcu_assign_pointer(wait->task, get_current_thread());
}

static inline void finish_rcuwait(struct rcuwait *wait)
{
    rcu_assign_pointer(wait->task, NULL);
    set_current_state(THREAD_RUNNABLE);
}

#endif
