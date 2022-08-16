/*
 * Copyright (c) 2017 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_DPC_H
#define _ONYX_DPC_H

#include <stddef.h>

#include <onyx/list.h>

struct dpc_work
{
    void (*funcptr)(void *context);
    void *context;
    struct list_head list_node;
};

typedef enum
{
    DPC_PRIORITY_HIGH = 0,
    DPC_PRIORITY_MEDIUM,
    DPC_PRIORITY_LOW
} dpc_priority;

#define DPC_POOL_NR_OBJS 8192

void dpc_init(void);
int dpc_schedule_work(struct dpc_work *work, dpc_priority prio);

#endif
