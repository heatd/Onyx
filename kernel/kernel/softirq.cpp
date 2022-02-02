/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <onyx/irq.h>
#include <onyx/net/netif.h>
#include <onyx/panic.h>
#include <onyx/percpu.h>
#include <onyx/softirq.h>
#include <onyx/timer.h>

PER_CPU_VAR(unsigned int pending_vectors);

bool softirq_may_handle()
{
    auto irqs_enabled = !irq_is_disabled();
    auto preemption_disabled = sched_is_preemption_disabled();

    return irqs_enabled && !preemption_disabled;
}

bool softirq_pending()
{
    return get_per_cpu(pending_vectors) != 0;
}

void softirq_handle()
{
    sched_disable_preempt();

    bool is_disabled = irq_is_disabled();

    irq_enable();

    auto pending = get_per_cpu(pending_vectors);

    if (pending & (1 << SOFTIRQ_VECTOR_TIMER))
    {
        timer_handle_events(platform_get_timer());
        pending &= ~(1 << SOFTIRQ_VECTOR_TIMER);
    }

#ifdef CONFIG_NET
    if (pending & (1 << SOFTIRQ_VECTOR_NETRX))
    {
        netif_do_rx();
        pending &= ~(1 << SOFTIRQ_VECTOR_NETRX);
    }
#endif

    write_per_cpu(pending_vectors, pending);

    if (is_disabled)
        irq_disable();

    sched_enable_preempt_no_softirq();
}

void softirq_try_handle()
{
    if (get_per_cpu(pending_vectors) && softirq_may_handle())
        softirq_handle();
}

void softirq_raise(enum softirq_vector vec)
{
    unsigned int mask = (1 << vec);

    auto flags = irq_save_and_disable();

    /* This is thread safe because you can't signal other CPUs's softirqs */
    auto pending = get_per_cpu(pending_vectors) | mask;

    write_per_cpu(pending_vectors, pending);

    irq_restore(flags);

    if (pending && softirq_may_handle())
        softirq_handle();
}
