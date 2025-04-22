/*
 * Copyright (c) 2017 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <assert.h>
#include <stdio.h>

#include <onyx/dpc.h>
#include <onyx/irq.h>
#include <onyx/scheduler.h>
#include <onyx/semaphore.h>
#include <onyx/spinlock.h>
#include <onyx/task_switching.h>
#include <onyx/vector.h>
#include <onyx/vm.h>
#include <onyx/wait_queue.h>

#include <onyx/mm/pool.hpp>

/* The work queue does need locks for insertion, because another CPU might try
 * to queue work in at the same time as us
 */
static memory_pool<dpc_work, MEMORY_POOL_USABLE_ON_IRQ> dpc_pool;

struct dpc_queue
{
    struct list_head items;
    struct spinlock lock;
    struct thread *thread;
    bool blocked;
};

static struct dpc_queue dpc_queues[3];

static bool dpc_has_work(struct dpc_queue *queue)
{
    return !list_is_empty(&queue->items);
}

static void dpc_process(struct dpc_queue *queue, unsigned long irq_flags)
{
    struct dpc_work *work, *next;
    DEFINE_LIST(items);
    list_splice_tail_init(&queue->items, &items);
    spin_unlock_irqrestore(&queue->lock, irq_flags);

    list_for_each_entry_safe (work, next, &items, list_node)
    {
        list_remove(&work->list_node);
        work->funcptr(work->context);
        dpc_pool.free(work);
    }

    irq_flags = spin_lock_irqsave(&queue->lock);
}

static void dpc_do_work(void *context)
{
    struct dpc_queue *queue = (struct dpc_queue *) context;
    unsigned long flags = spin_lock_irqsave(&queue->lock);
    while (true)
    {
        if (dpc_has_work(queue))
            dpc_process(queue, flags);

        queue->blocked = true;
        set_current_state(THREAD_UNINTERRUPTIBLE);
        if (dpc_has_work(queue))
        {
            queue->blocked = false;
            set_current_state(THREAD_RUNNABLE);
            continue;
        }

        spin_unlock_irqrestore(&queue->lock, flags);
        sched_yield();
        flags = spin_lock_irqsave(&queue->lock);
    }
}

static void dpc_add_work(struct dpc_queue *queue, struct dpc_work *work)
{
    unsigned long flags = spin_lock_irqsave(&queue->lock);
    list_add_tail(&work->list_node, &queue->items);
    if (queue->blocked)
    {
        thread_wake_up(queue->thread);
        queue->blocked = false;
    }
    spin_unlock_irqrestore(&queue->lock, flags);
}

static int dpc_sched_prio[3] = {
    /*[DPC_PRIORITY_HIGH] =*/SCHED_PRIO_HIGH,
    SCHED_PRIO_NORMAL,
    SCHED_PRIO_LOW,
};

void dpc_init(void)
{
    struct dpc_queue *queue;

    for (unsigned int i = 0; i < 3; i++)
    {
        queue = &dpc_queues[i];
        INIT_LIST_HEAD(&queue->items);
        spin_lock_init(&queue->lock);
        queue->blocked = false;
        queue->thread = sched_create_thread(dpc_do_work, THREAD_KERNEL, queue);
        CHECK(queue->thread != NULL);
        queue->thread->priority = dpc_sched_prio[i];
        sched_start_thread(queue->thread);
    }
}

int dpc_schedule_work(dpc_work *_work, dpc_priority prio)
{
    /* We'll allocate a copy of the dpc_work, and if we fail, the IRQ simply isn't handled.
     * Note that we're only allocating memory here.
     */
    dpc_work *work = dpc_pool.allocate();
    if (!work)
    {
        printf("slab_allocate failed: dpc work request being discarded!\n");
        return -1;
    }

    memcpy(work, _work, sizeof(struct dpc_work));
    dpc_add_work(&dpc_queues[prio], work);
    return 0;
}
