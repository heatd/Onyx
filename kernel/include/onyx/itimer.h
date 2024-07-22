/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_ITIMER_H
#define _ONYX_ITIMER_H

#include <onyx/spinlock.h>
#include <onyx/timer.h>

#define ITIMER_COUNT 3

struct itimer
{
    int which;
    struct process *p;
    struct spinlock lock;
    hrtime_t interval_delta;
    struct clockevent ev;
    bool armed;

#ifdef __cplusplus
    int arm(hrtime_t interval, hrtime_t initial);
    int disarm();

    ~itimer()
    {
        disarm();
    }
#endif
};

struct process;
void itimer_init(struct process *p);

#endif
