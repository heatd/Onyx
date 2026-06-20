/*
 * Copyright (c) 2016 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/scheduler.h>

struct sched_rq
{
    struct spinlock lock;
    struct thread *thread_queues_head[NUM_PRIO];
    struct thread *thread_queues_tail[NUM_PRIO];
    unsigned int tasks_in_queues;
};
