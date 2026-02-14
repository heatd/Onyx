/*
 * Copyright (c) 2016 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_PREEMPT_H
#define _ONYX_PREEMPT_H

#include <onyx/compiler.h>
#include <onyx/irqflags.h>
#include <onyx/percpu.h>

#include <linux/irqflags_lockdep.h>

__BEGIN_CDECLS

// clang-format off
#ifndef _THIS_IP_
#define _THIS_IP_  ({ __label__ __here; __here: (unsigned long)&&__here; })
#endif
// clang-format on

void sched_enable_pulse();

void sched_handle_preempt(bool may_softirq);

extern unsigned long preemption_counter;

static __always_inline bool sched_is_preemption_disabled()
{
    return get_per_cpu(preemption_counter) > 0;
}

static __always_inline unsigned long sched_get_preempt_counter()
{
    return get_per_cpu(preemption_counter);
}

static __always_inline void __sched_enable_preempt()
{
    unsigned long flags;

    (void) flags;
    dec_per_cpu(preemption_counter);
#ifdef CONFIG_LOCKDEP
    if (get_per_cpu(preemption_counter) == 0)
    {
        flags = irq_save_and_disable();
        lockdep_softirqs_on(_THIS_IP_);
        irq_restore(flags);
    }
#endif
}

static __always_inline void sched_enable_preempt_no_softirq()
{
    __sched_enable_preempt();
}

static __always_inline void sched_enable_preempt()
{
    // If preemption is enabled, try to do various tasks
    // softirq, rescheduling, etc
    unsigned long flags;

    (void) flags;
    bool zero = dec_and_test_pcpu(preemption_counter);
    if (unlikely(zero))
    {
#ifdef CONFIG_LOCKDEP
        flags = irq_save_and_disable();
        lockdep_softirqs_on(_THIS_IP_);
        irq_restore(flags);
#endif
        if (likely(!irq_is_disabled()))
            sched_handle_preempt(true);
    }
}

static __always_inline void sched_disable_preempt()
{
    unsigned long flags;

    (void) flags;
    inc_per_cpu(preemption_counter);
#ifdef CONFIG_LOCKDEP
    if (get_per_cpu(preemption_counter) == 1)
    {
        flags = irq_save_and_disable();
        lockdep_softirqs_off(_THIS_IP_);
        irq_restore(flags);
    }
#endif
}

__END_CDECLS

#endif
