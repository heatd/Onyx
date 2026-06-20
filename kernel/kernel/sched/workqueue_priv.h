/*
 * Copyright (c) 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/mutex.h>
#include <onyx/wait_queue.h>

#include <linux/workqueue.h>

/* The base design is the following:
 * First, we have the worker thread. This worker thread represents a single thread, pops work
 * elements from $elsewhere. If blocked, we want to spawn more threads.
 * Secondly, we have the worker_pool. This is the set of threads + a work list. Individual workers
 * pop work from here. When a worker blocks, the scheduler is notified and creates a new thread.
 * This worker is added to the pool.
 * Thirdly, pool_workqueue allows us to manage per-pool work concurrency.
 * Fourth, workqueue_struct does the high level management of the wq. It has $NR_CPUS
 * pool_workqueues. In case of unbound wqs, these all point to the same pool.
 */

struct pool_workqueue;
struct worker_pool;

#define WQ_MAX_MAXACTIVE 2048
#define WQ_DFL_MAXACTIVE 1024
#define WQ_MIN_MAXACTIVE 16

struct workqueue_struct
{
    const char *name;
    unsigned int flags;
    struct mutex lock;
    int max_active;
    struct pool_workqueue *queues[CONFIG_SMP_NR_CPUS];
    struct list_head queue_list_node;
};

struct pool_workqueue
{
    struct workqueue_struct *owner;
    struct worker_pool *worker_pool;
    struct spinlock lock;
    int nr_active;
    /* Work that can't be dispatched to the worker pool immediately gets queued here. As work
     * completes, we'll queue these off. */
    struct list_head inactive_list;
};

#define WORKER_POOL_UNBOUND (1 << 0)
#define WORKER_POOL_HIGHPRI (1 << 1)
struct worker_pool
{
    struct spinlock lock;
    unsigned int flags;
    unsigned int cpu;
    unsigned int nr_running;
    unsigned int nr_idle;
    struct list_head work_list;
    struct list_head worker_list;
    struct wait_queue wq;
};

struct worker
{
    struct list_head node;
    struct worker_pool *pool;
    struct thread *thread;
    bool running : 1;
};

#define WORK_DATA_QUEUED (1 << 0)
