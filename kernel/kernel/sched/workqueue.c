/*
 * Copyright (c) 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdarg.h>
#include <stdio.h>

#include <onyx/cpu.h>
#include <onyx/err.h>
#include <onyx/init.h>
#include <onyx/irqflags.h>
#include <onyx/mm/slab.h>
#include <onyx/page.h>
#include <onyx/scheduler.h>

#include <linux/debug_locks.h>

#include "workqueue_priv.h"

struct workqueue_struct *system_long_wq, *system_wq, *system_percpu_wq, *system_dfl_wq,
    *system_unbound_wq, *system_highpri_wq;

DECLARE_MUTEX(workqueue_list_lock);
DEFINE_LIST(workqueue_list);

/* 1 normal, 1 highpri */
#define NR_VARIANTS 2

static struct worker_pool *pcpu_pools[CONFIG_SMP_NR_CPUS * NR_VARIANTS];
static struct worker_pool *unbound_pool[NR_VARIANTS];

static unsigned long do_work(struct worker_pool *pool, struct work_struct *work)
{
    struct thread *curr = get_current_thread();
    struct pool_workqueue *pwq;
    struct list_head *node;
    unsigned long flags;
    int lockdep_depth;
    int to_queue, i;
    work_func_t fn;

    pwq = (struct pool_workqueue *) (READ_ONCE(work->data) & ~WORK_DATA_QUEUED);
    smp_store_mb(work->data, 0);

    lockdep_depth = lockdep_depth(curr);
    fn = work->func;
    fn(work);

    if (WARN_ON_ONCE(irq_is_disabled() || lockdep_depth(curr) != lockdep_depth ||
                     sched_is_preemption_disabled() || rcu_read_lock_held()))
    {
        pr_err("workqueue: workqueue item leaked lock, preempt counter or RCU read lock\n");
        pr_err("           irqs:%u lockdep depth:%u preempt:%lu rcu:%u\n", irq_is_disabled(),
               lockdep_depth(curr), sched_get_preempt_counter(), rcu_read_lock_held());
        pr_err("           work fn: %pS work: %p\n", fn, work);
        debug_show_held_locks((void *) curr);
    }

    flags = spin_lock_irqsave(&pool->lock);

    to_queue = pwq->owner->max_active - __atomic_sub_fetch(&pwq->nr_active, 1, __ATOMIC_RELEASE);
    /* If we need to, queue inactive work onto our worker pool */
    if (unlikely(to_queue > 0 && !list_is_empty(&pwq->inactive_list)))
    {
        for (i = 0; i < to_queue; i++)
        {
            if (list_is_empty(&pwq->inactive_list))
                break;
            node = list_first_element(&pwq->inactive_list);
            list_remove(node);
            list_add_tail(node, &pool->work_list);
            __atomic_add_fetch(&pwq->nr_active, 1, __ATOMIC_RELAXED);
        }
    }

    return flags;
}

static bool worker_pool_needs_more(struct worker_pool *pool)
{
    lockdep_assert_held(&pool->lock);
    /* We only need to create more idle workers if 1) we are going to run more work 2) there are no
     * idle workers. Condition (1) is important, because otherwise we would mindlessly create
     * workers. Only when (1) happens, can a worker get stuck sleeping and not handling more work.
     */
    return !list_is_empty(&pool->work_list) && !pool->nr_idle;
}

static void wake_pool(struct worker_pool *pool)
{
    lockdep_assert_held(&pool->lock);

    /* If no one else is running, and there's work to be done, wake someone up. */
    if (!pool->nr_running && !list_is_empty(&pool->work_list))
        wait_queue_wake(&pool->wq);
}

void wq_worker_sleeping(struct thread *thread)
{
    struct worker *worker = thread->data;
    struct worker_pool *pool = worker->pool;
    unsigned long flags;

    flags = spin_lock_irqsave(&pool->lock);
    if (worker->running)
        pool->nr_running--;
    wake_pool(pool);
    spin_unlock_irqrestore(&pool->lock, flags);
}

void wq_worker_running(struct thread *thread)
{
    struct worker *worker = thread->data;
    struct worker_pool *pool = worker->pool;
    unsigned long flags;

    flags = spin_lock_irqsave(&pool->lock);
    if (worker->running)
        pool->nr_running++;
    spin_unlock_irqrestore(&pool->lock, flags);
}

/**
 * @brief Create a new worker for a pool
 * Note: this function drops the pool lock
 * If the function fails, it will leave the pool lock unlocked.
 * @param pool Pool to create for
 * @param irq_flags in-out parameter for irq flags
 * @return true if it succeeded, else false
 */
static bool worker_pool_create_worker(struct worker_pool *pool, unsigned long *irq_flags);

/**
 * @brief Create a worker for the worker pool (called from worker threads)
 * Note: this function drops the pool lock.
 * @param pool Pool to create for
 * @param irq_flags in-out parameter for irq flags
 */
static void worker_pool_create_more(struct worker_pool *pool, unsigned long *irq_flags)
{
    bool ret = worker_pool_create_worker(pool, irq_flags);
    if (!ret)
    {
        /* Not much we can do here. The workqueue may stall severely. It is life. This Should Not
         * Happen. */
        pr_err("workqueue: failed to create a new worker\n");
        *irq_flags = spin_lock_irqsave(&pool->lock);
    }
}

static void do_work_loop(struct worker *worker, struct worker_pool *pool, unsigned long *irq_flags)
{
    struct work_struct *work;

    lockdep_assert_held(&pool->lock);
    pool->nr_running++;
    worker->running = true;

    while (!list_is_empty(&pool->work_list))
    {
        work = list_first_entry(&pool->work_list, struct work_struct, list);
        list_remove(&work->list);
        spin_unlock_irqrestore(&pool->lock, *irq_flags);
        *irq_flags = do_work(pool, work);
    }

    WARN_ON(!worker->running);
    pool->nr_running--;
    worker->running = false;
}

static void worker_main(void *priv)
{
    struct worker *worker = priv;
    struct worker_pool *pool;
    unsigned long flags;

    pool = worker->pool;
    flags = spin_lock_irqsave(&pool->lock);
    for (;;)
    {

        if (worker_pool_needs_more(pool))
        {
            /* Needs more workers, lets create one. */
            worker_pool_create_more(pool, &flags);
        }

        do_work_loop(worker, pool, &flags);
        pool->nr_idle++;
        wait_for_event_locked_irqsave(&pool->wq, !list_is_empty(&pool->work_list), &pool->lock,
                                      flags);
        pool->nr_idle--;
    }
}

static inline bool test_and_set(unsigned long *word, unsigned long val)
{
    unsigned long old = READ_ONCE(*word);
    do
    {
        if (old & val)
            return false;
    } while (!__atomic_compare_exchange_n(word, &old, old | val, false, __ATOMIC_RELEASE,
                                          __ATOMIC_RELAXED));
    return true;
}

static struct pool_workqueue *queue_pick_pwq(struct workqueue_struct *wq, int cpu)
{
    struct pool_workqueue *pwq;
    unsigned int i;

    /* Quite simple: just return the first one */
    if (wq->flags & WQ_UNBOUND)
        return wq->queues[0];

    if (cpu != WORK_CPU_UNBOUND)
    {
        WARN_ON((unsigned int) cpu >= get_nr_cpus());
        return wq->queues[cpu];
    }

    /* Ok, user picked "unbound" cpu. This workqueue is percpu. Lets prefer current - but if we
     * can't queue it (because max_active won't let us), then pick any queue that we may be able
     * to queue on. If there is no queue we can queue on, then prefer current again. */
    pwq = wq->queues[get_cpu_nr()];
    if (likely(READ_ONCE(pwq->nr_active) < wq->max_active))
        return pwq;

    for (i = 0; i < get_nr_cpus(); i++)
    {
        if (READ_ONCE(wq->queues[i]->nr_active) < wq->max_active)
            return wq->queues[i];
    }

    /* I guess we'll have to keep this work inactive.. */
    return pwq;
}

static void pool_queue_inactive(struct pool_workqueue *pwq, struct work_struct *work)
{
    list_add_tail(&work->list, &pwq->inactive_list);
}

static void pool_queue_work(struct pool_workqueue *pwq, struct work_struct *work)
{
    struct worker_pool *pool = pwq->worker_pool;

    lockdep_assert_held(&pool->lock);
    __atomic_add_fetch(&pwq->nr_active, 1, __ATOMIC_RELAXED);
    work->data = (unsigned long) pwq | WORK_DATA_QUEUED;

    list_add_tail(&work->list, &pool->work_list);
    if (pwq->owner->flags & WQ_UNBOUND || !pool->nr_running)
        wake_pool(pool);
}

bool queue_work_on(int cpu, struct workqueue_struct *wq, struct work_struct *work)
{
    struct pool_workqueue *pwq;
    struct worker_pool *pool;
    unsigned long irq_flags;

    /* Check if someone queued this work before. */
    if (!test_and_set(&work->data, WORK_DATA_QUEUED))
        return false;

    irq_flags = irq_save_and_disable();

    pwq = queue_pick_pwq(wq, cpu);
    pool = pwq->worker_pool;

    spin_lock(&pool->lock);
    /* nr_active accounting is purposefully best-effort - we don't want to take the lock if we
     * don't need to. */
    if (READ_ONCE(pwq->nr_active) < wq->max_active)
        pool_queue_work(pwq, work);
    else
        pool_queue_inactive(pwq, work);
    spin_unlock(&pool->lock);
    irq_restore(irq_flags);
    return true;
}

static bool worker_pool_create_worker(struct worker_pool *pool, unsigned long *irq_flags)
{
    struct worker *worker;

    spin_unlock_irqrestore(&pool->lock, *irq_flags);

    worker = kmalloc(sizeof(*worker), GFP_KERNEL);
    if (!worker)
        return false;
    worker->thread = sched_create_thread(worker_main, THREAD_KERNEL | THREAD_WORKQUEUE, worker);
    if (!worker->thread)
    {
        kfree(worker);
        return false;
    }

    if (pool->flags & WORKER_POOL_HIGHPRI)
        worker->thread->priority = 15;

    worker->thread->data = worker;
    worker->pool = pool;
    worker->running = false;

    *irq_flags = spin_lock_irqsave(&pool->lock);
    list_add_tail(&worker->node, &pool->worker_list);

    worker->thread->task_affinity = cpumask_one(pool->cpu);
    sched_start_thread(worker->thread);

    return true;
}

static struct worker_pool *worker_pool_create(unsigned int cpu, unsigned int pool_flags)
{
    struct worker_pool *pool;
    unsigned long irq_flags;

    pool = kmalloc(sizeof(*pool), GFP_KERNEL);
    if (!pool)
        return NULL;

    spinlock_init(&pool->lock);
    INIT_LIST_HEAD(&pool->work_list);
    INIT_LIST_HEAD(&pool->worker_list);
    WARN_ON(cpu != 0 && (pool_flags & WORKER_POOL_UNBOUND));
    pool->cpu = cpu;
    pool->flags = pool_flags;
    pool->nr_running = pool->nr_idle = 0;
    init_wait_queue_head(&pool->wq);

    irq_flags = spin_lock_irqsave(&pool->lock);
    if (!worker_pool_create_worker(pool, &irq_flags))
    {
        kfree(pool);
        return NULL;
    }
    spin_unlock_irqrestore(&pool->lock, irq_flags);
    return pool;
}

static struct pool_workqueue *pwq_alloc(struct workqueue_struct *wq, int index)
{
    bool is_unbound = wq->flags & WQ_UNBOUND;
    bool hipri = wq->flags & WQ_HIGHPRI;
    struct pool_workqueue *pwq;

    pwq = kmalloc(sizeof(*pwq), GFP_KERNEL);
    if (!pwq)
        return NULL;
    spinlock_init(&pwq->lock);
    pwq->owner = wq;
    INIT_LIST_HEAD(&pwq->inactive_list);
    pwq->nr_active = 0;

    if (is_unbound)
        pwq->worker_pool = unbound_pool[(int) hipri];
    else
        pwq->worker_pool = pcpu_pools[(index * NR_VARIANTS) + (int) hipri];

    /* Should not happen!!! worker pool should exist. */
    if (WARN_ON(!pwq->worker_pool))
    {
        pr_err("worker pool for %s%u%s not found\n", is_unbound ? "unbound" : "cpu", index,
               hipri ? " (hipri)" : "");
        kfree(pwq);
        return NULL;
    }

    return pwq;
}

static bool wq_init_pools(struct workqueue_struct *wq)
{
    bool is_unbound = wq->flags & WQ_UNBOUND;
    struct pool_workqueue *pwq = NULL;
    unsigned int i;

    if (is_unbound)
    {
        pwq = pwq_alloc(wq, 0);
        if (!pwq)
            return false;
    }

    for (i = 0; i < get_nr_cpus(); i++)
    {
        if (!is_unbound)
        {
            pwq = pwq_alloc(wq, i);
            if (!pwq)
                goto err_rollback;
        }

        wq->queues[i] = pwq;
    }

    return true;
err_rollback:
    while (i--)
        kfree(wq->queues[i]);
    return false;
}

__printf(1, 4) struct workqueue_struct *alloc_workqueue(const char *fmt, unsigned int flags,
                                                        int max_active, ...)
{
    struct workqueue_struct *wq;
    va_list va;

    wq = kmalloc(sizeof(*wq), GFP_KERNEL);
    if (!wq)
        goto err_out;

    mutex_init(&wq->lock);
    wq->flags = flags;
    if (!max_active)
        max_active = WQ_DFL_MAXACTIVE;
    wq->max_active = max(max_active, WQ_MIN_MAXACTIVE);
    wq->max_active = min(wq->max_active, WQ_MAX_MAXACTIVE);
    va_start(va, max_active);
    wq->name = kvasprintf(GFP_KERNEL, fmt, va);
    va_end(va);
    if (IS_ERR(wq->name))
        goto err_free_wq;

    if (!wq_init_pools(wq))
        goto err_free_name;

    mutex_lock(&workqueue_list_lock);
    list_add_tail(&wq->queue_list_node, &workqueue_list);
    mutex_unlock(&workqueue_list_lock);
    return wq;
err_free_name:
    kfree((void *) wq->name);
err_free_wq:
    kfree(wq);
err_out:
    if (flags & WQ_PANIC)
        panic("failed to create workqueue");
    return NULL;
}

static void wq_init(void)
{
    unsigned int nr_cpus = get_nr_cpus(), i;

    pr_info("workqueue: initializing workers for %u cpus\n", nr_cpus);

    for (i = 0; i < nr_cpus * NR_VARIANTS; i++)
    {
        pcpu_pools[i] = worker_pool_create(i / 2, (i % 2) ? WORKER_POOL_HIGHPRI : 0);
        CHECK(pcpu_pools[i] != NULL);
    }

    for (i = 0; i < NR_VARIANTS; i++)
    {
        unbound_pool[i] =
            worker_pool_create(0, WORKER_POOL_UNBOUND | ((i % 2) ? WORKER_POOL_HIGHPRI : 0));
        CHECK(unbound_pool[i] != NULL);
    }

    system_percpu_wq = alloc_workqueue("events", WQ_PERCPU | WQ_PANIC, 0);
    system_wq = system_percpu_wq;
    system_highpri_wq = alloc_workqueue("events_highpri", WQ_HIGHPRI | WQ_PERCPU | WQ_PANIC, 0);
    system_long_wq = alloc_workqueue("events_long", WQ_PERCPU | WQ_PANIC, 0);
    system_unbound_wq = alloc_workqueue("events_unbound", WQ_UNBOUND | WQ_PANIC, WQ_MAX_MAXACTIVE);
    system_dfl_wq = system_unbound_wq;
}
INIT_LEVEL_CORE_AFTER_SCHED_ENTRY(wq_init);
