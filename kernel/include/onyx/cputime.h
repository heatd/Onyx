/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_CPUTIME_H
#define _ONYX_CPUTIME_H

#include <onyx/clock.h>

void context_tracking_enter_kernel(void);
void context_tracking_exit_kernel(void);
void do_cputime_accounting(void);
struct thread;
void cputime_restart_accounting(struct thread *t);

enum thread_context
{
    THREAD_CONTEXT_USER = 0,

    /* Thread context is also used as a counter to detect kernel mode recursion */
    THREAD_CONTEXT_KERNEL_MIN
};

/* Essentially our system works like this: we gather times periodically,
 * through our timeslices. Each change of scheduler timeslice(through the
 * scheduler preempting us out) or CPU mode(kernel <--> user) changes our timeslice,
 * which makes it so we can record system and user times separately.
 */
struct thread_cputime_info
{
    hrtime_t system_time;
    hrtime_t user_time;
    hrtime_t last_timeslice_timestamp;

    /* 32-bits should be fine for any kind of recursive preemption */
    uint32_t context;
};

void cputime_info_init(struct thread *t);

#endif
