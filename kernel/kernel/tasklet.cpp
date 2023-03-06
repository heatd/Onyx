/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>

#include <onyx/init.h>
#include <onyx/irq.h>
#include <onyx/list.h>
#include <onyx/percpu.h>
#include <onyx/smp.h>
#include <onyx/softirq.h>
#include <onyx/tasklet.h>

PER_CPU_VAR(struct list_head pending_tasklet_list);

void tasklet_ctor(unsigned int cpu)
{
    INIT_LIST_HEAD(get_per_cpu_ptr_any(pending_tasklet_list, cpu));
}

void tasklet_schedule(tasklet *t)
{
    // Make sure we're not running
    assert(t->flags == 0);

    // Disable IRQs so we can use this in hardirq context
    auto flags = irq_save_and_disable();

    auto list = get_per_cpu_ptr(pending_tasklet_list);

    list_add_tail(&t->list_node, list);

    t->flags |= TASKLET_PENDING;

    irq_restore(flags);

    softirq_raise(SOFTIRQ_VECTOR_TASKLET);
}

void tasklet_run()
{
    struct list_head to_run;
    // Disable IRQs for a bit, while we copy the list
    // We copy it so we hold the noirq context for as little time as possible
    auto flags = irq_save_and_disable();

    auto list = get_per_cpu_ptr(pending_tasklet_list);

    list_move(&to_run, list);

    irq_restore(flags);

    list_for_every_safe (&to_run)
    {
        tasklet *t = container_of(l, tasklet, list_node);
        t->flags.or_fetch(TASKLET_RUNNING, mem_order::acquire);
        t->func(t->context);
        list_remove(&t->list_node);
        t->flags.store(0, mem_order::release);
    }
}

INIT_LEVEL_CORE_PERCPU_CTOR(tasklet_ctor);
