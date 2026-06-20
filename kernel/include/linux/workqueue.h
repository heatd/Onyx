/*
 * Copyright (c) 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _LINUX_WORKQUEUE_H
#define _LINUX_WORKQUEUE_H

#include <linux/timer.h>
#include <linux/list.h>
#include <linux/lockdep.h>

struct workqueue_struct;
struct work_struct;

typedef void (*work_func_t)(struct work_struct *work);

struct work_struct
{
    unsigned long data;
    struct list_head list;
    work_func_t func;
#ifdef CONFIG_LOCKDEP
    struct lockdep_map lockdep_map;
#endif
};

struct delayed_work
{
    struct work_struct work;
};

extern struct workqueue_struct *system_long_wq, *system_wq, *system_percpu_wq,
*system_dfl_wq, *system_unbound_wq, *system_highpri_wq;

#define WORK_CPU_UNBOUND (-1)

bool queue_work_on(int cpu, struct workqueue_struct *wq, struct work_struct *work);

static inline bool queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
    return queue_work_on(WORK_CPU_UNBOUND, wq, work);
}

static inline void schedule_work(struct work_struct *work)
{
    queue_work(system_percpu_wq, work);
}

#define INIT_WORK(work, workfn) \
do {                            \
    (work)->data = 0;           \
    (work)->func = workfn;      \
} while (0)

#define INIT_WORK_ONSTACK(work, workfn) INIT_WORK(work, workfn)

bool flush_work(struct work_struct *work);

static inline void destroy_work_on_stack(struct work_struct *work)
{
}

#define WQ_UNBOUND (1 << 0)
#define WQ_HIGHPRI (1 << 1)
#define WQ_PERCPU  (1 << 2)
#define WQ_PANIC   (1 << 3)

__printf(1, 4)
struct workqueue_struct *alloc_workqueue(const char *fmt,
						unsigned int flags,
						int max_active, ...);

void destroy_workqueue(struct workqueue_struct *wq);

#endif
