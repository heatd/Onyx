/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_PREEMPT_H
#define _ONYX_PREEMPT_H

#include <onyx/compiler.h>
#include <onyx/percpu.h>

#include <platform/irq.h>

__BEGIN_CDECLS

void sched_enable_pulse();

void sched_handle_preempt(bool may_softirq);

extern unsigned long preemption_counter;

__always_inline bool sched_is_preemption_disabled()
{
    return get_per_cpu(preemption_counter) > 0;
}

__always_inline unsigned long sched_get_preempt_counter()
{
    return get_per_cpu(preemption_counter);
}

__always_inline void __sched_enable_preempt()
{
    dec_per_cpu(preemption_counter);
}

__always_inline void sched_enable_preempt_no_softirq()
{
    __sched_enable_preempt();
}

__always_inline void sched_enable_preempt()
{
    // If preemption is enabled, try to do various tasks
    // softirq, rescheduling, etc
    if (unlikely(dec_and_test_pcpu(preemption_counter)) && likely(!irq_is_disabled()))
        sched_handle_preempt(true);
}

__always_inline void sched_disable_preempt()
{
    inc_per_cpu(preemption_counter);
}

__END_CDECLS

#endif
