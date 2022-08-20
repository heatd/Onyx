/*
 * Copyright (c) 2017 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
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

#include <onyx/mm/pool.hpp>

/* The work queue does need locks for insertion, because another CPU might try
 * to queue work in at the same time as us
 */
static struct semaphore dpc_work_semaphore = {};
static thread_t *dpc_thread;
memory_pool<dpc_work, MEMORY_POOL_USABLE_ON_IRQ> dpc_pool;

class dpc_queue
{
    spinlock wq_lock{};
    list_head queue{};

    bool has_work_locked()
    {
        return !list_is_empty(&queue);
    }

public:
    constexpr dpc_queue()
    {
        INIT_LIST_HEAD(&queue);
        spinlock_init(&wq_lock);
    }

    void do_work()
    {
        while (true)
        {
            dpc_work *work = nullptr;

            {
                scoped_lock<spinlock, true> g{wq_lock};
                if (!has_work_locked())
                    return;
                auto l = list_first_element(&queue);
                work = container_of(l, dpc_work, list_node);
                list_remove(l);
            }

            work->funcptr(work->context);
            dpc_pool.free(work);
        }
    }

    void add(dpc_work *w)
    {
        scoped_lock<spinlock, true> g{wq_lock};
        list_add_tail(&w->list_node, &queue);
    }
};

dpc_queue dpc_queues[3];

void dpc_do_work(void *context)
{
    while (true)
    {
        sem_wait(&dpc_work_semaphore);

        /* Process work */
        for (int i = 0; i < 3; i++)
        {
            /* Let's process DPC work */
            dpc_queues[i].do_work();
        }
    }
}

void dpc_init()
{
    sem_init(&dpc_work_semaphore, 0);

    dpc_thread = sched_create_thread(dpc_do_work, THREAD_KERNEL, nullptr);
    assert(dpc_thread != nullptr);
    dpc_thread->priority = SCHED_PRIO_VERY_HIGH;

    sched_start_thread(dpc_thread);
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

    dpc_queues[prio].add(work);

    sem_signal(&dpc_work_semaphore);

    return 0;
}
