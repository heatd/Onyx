/*
 * Copyright (c) 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/init.h>
#include <onyx/process.h>
#include <onyx/rcupdate.h>
#include <onyx/task_switching.h>

#define TIMEOUT (10 * NS_PER_SEC)

void stack_trace_thread(struct thread *thread);

static void dump_hung_task(struct process *task)
{
    pr_warn("hung_task_detector: task %s (%d) has been blocked for more than 10 seconds...\n",
            task->comm, task->pid_);
    stack_trace_thread(task->thr);
}

static void check_for_hung_tasks(void)
{
    struct process *task;
    hrtime_t now;
    int status;

    now = clocksource_get_time();
    rcu_read_lock();
    list_for_each_entry_rcu (task, &tasklist, tasklist_node)
    {
        /* Hasn't switched yet, that's fine. */
        if (task->last_switch_time == 0)
            continue;
        /* Not its time, yet. */
        if (task->last_switch_time + TIMEOUT > now)
            continue;

        /* Interruptible tasks can stay blocked all they want */
        status = READ_ONCE(task->thr->status);
        if (status == THREAD_INTERRUPTIBLE || status == THREAD_DEAD || status == THREAD_STOPPED)
            continue;
        dump_hung_task(task);
    }
    rcu_read_unlock();
}

static void hung_task_detector(void *unused)
{
    for (;;)
    {
        sched_sleep(TIMEOUT);
        check_for_hung_tasks();
    }
}

static void hung_task_init(void)
{
    struct thread *thread;

    thread = sched_create_thread(hung_task_detector, THREAD_KERNEL, NULL);
    CHECK(thread != NULL);
    thread->priority = SCHED_PRIO_VERY_LOW;
    sched_start_thread(thread);
}

INIT_LEVEL_CORE_KERNEL_ENTRY(hung_task_init);
