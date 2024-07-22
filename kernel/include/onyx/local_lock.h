/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_LOCAL_LOCK_H
#define _ONYX_LOCAL_LOCK_H

#include <onyx/lock_annotations.h>
#include <onyx/preempt.h>

#include <platform/irq.h>

/* Linux-like local_lock implementation as defined in
 * https://docs.kernel.org/locking/locktypes.html#local-lock
 */
struct CAPABILITY("local lock") local_lock
{
#ifdef __cplusplus
    /* We need this dummy[0] to force a zero-sized struct in C++*/
    int dummy[0];
#endif
};

#define local_lock_init(x) ((void) (x))

static inline void local_lock(struct local_lock *ll) ACQUIRE(ll) NO_THREAD_SAFETY_ANALYSIS
{
    sched_disable_preempt();
}

static inline void local_unlock(struct local_lock *ll) RELEASE(ll) NO_THREAD_SAFETY_ANALYSIS
{
    sched_enable_preempt();
}

static inline void local_unlock_nosoftirq(struct local_lock *ll)
    RELEASE(ll) NO_THREAD_SAFETY_ANALYSIS
{
    sched_enable_preempt_no_softirq();
}

static inline unsigned long local_lock_irqsave(struct local_lock *ll)
    ACQUIRE(ll) NO_THREAD_SAFETY_ANALYSIS
{
    return irq_save_and_disable();
}

static inline void local_unlock_irqrestore(struct local_lock *ll, unsigned long flags)
    RELEASE(ll) NO_THREAD_SAFETY_ANALYSIS
{
    irq_restore(flags);
}

#endif
