/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#include <sys/times.h>

#include <onyx/process.h>
#include <onyx/scheduler.h>
#include <onyx/thread.h>

/* This needs to run with IRQs disabled */
void do_cputime_accounting(void)
{
    auto current = get_current_thread();
    auto current_process = get_current_process();

    auto now = clocksource_get_time();
    auto &timeinfo = current->cputime_info;

    hrtime_delta_t delta = now - timeinfo.last_timeslice_timestamp;

    /* Note that we must use atomic adds to prevent race conditions here. */

    if (timeinfo.context != THREAD_CONTEXT_USER)
    {
        timeinfo.system_time += delta;
        if (current_process)
            __atomic_add_fetch(&current_process->system_time, delta, __ATOMIC_RELAXED);
    }
    else
    {
        timeinfo.user_time += delta;
        if (current_process)
            __atomic_add_fetch(&current_process->user_time, delta, __ATOMIC_RELAXED);
    }

    timeinfo.last_timeslice_timestamp = now;
}

void context_tracking_enter_kernel(void)
{
    auto flags = irq_save_and_disable();

    auto current = get_current_thread();
    if (current) [[likely]]
    {
        if (current->cputime_info.context == THREAD_CONTEXT_USER)
        {
            do_cputime_accounting();
        }

        current->cputime_info.context++;
    }

    irq_restore(flags);
}

void context_tracking_exit_kernel(void)
{
    auto flags = irq_save_and_disable();

    auto current = get_current_thread();
    if (current) [[likely]]
    {
        if (current->cputime_info.context == THREAD_CONTEXT_KERNEL_MIN)
        {
            do_cputime_accounting();
        }

        current->cputime_info.context--;
    }

    irq_restore(flags);
}

void cputime_info_init(struct thread *t)
{
    t->cputime_info.context =
        t->flags & THREAD_KERNEL ? THREAD_CONTEXT_KERNEL_MIN : THREAD_CONTEXT_USER;
    t->cputime_info.system_time = t->cputime_info.user_time = 0;
    t->cputime_info.last_timeslice_timestamp = 0;
}

clock_t sys_times(struct tms *buf)
{
    /* Thankfully, since we've entered kernel mode a few ns/us ago, we
     * don't need to take into account these last few moments. The accuracy loss should be minimal.
     */
    struct process *current = get_current_process();

    struct tms b = {};
    b.tms_stime = current->system_time / NS_PER_MS;
    b.tms_utime = current->user_time / NS_PER_MS;
    b.tms_cutime = current->children_utime;
    b.tms_cstime = current->children_stime;

    if (copy_to_user(buf, &b, sizeof(struct tms)) < 0)
        return -EFAULT;
    return clocksource_get_time() / NS_PER_MS;
}

void cputime_restart_accounting(thread *t)
{
    t->cputime_info.last_timeslice_timestamp = clocksource_get_time();
}
