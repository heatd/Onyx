/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_TASKLET_H
#define _ONYX_TASKLET_H

#include <onyx/list.h>
#include <onyx/types.h>

#include <onyx/atomic.hpp>

#define TASKLET_PENDING (1U << 0)
#define TASKLET_RUNNING (1U << 1)

struct tasklet
{
    void (*func)(void *);
    void *context;
    atomic<u32> flags{0};
    struct list_head list_node;
    tasklet(void (*f)(void *), void *c) : func{f}, context{c}
    {
    }
};

void tasklet_run();
void tasklet_schedule(tasklet *t);

#endif
