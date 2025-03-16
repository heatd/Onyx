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
    /* TODO: Fix this. We're screwing up system_time vs user_time *hard* on, e.g, make workloads.
     * Replacing with just counting ticks. */
    return;

#if 0
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
#endif
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
    tg_cputime_clock_t(current, &b.tms_utime, &b.tms_stime);
    b.tms_cutime = READ_ONCE(current->sig->cutime) / NS_PER_MS;
    b.tms_cstime = READ_ONCE(current->sig->cstime) / NS_PER_MS;

    if (copy_to_user(buf, &b, sizeof(struct tms)) < 0)
        return -EFAULT;
    return clocksource_get_time() / NS_PER_MS;
}

void cputime_restart_accounting(thread *t)
{
    t->cputime_info.last_timeslice_timestamp = clocksource_get_time();
}

static PER_CPU_VAR(struct kcputime cputime);

void kcputime_add(enum kcputimes time, hrtime_t delta)
{
    struct kcputime *cpu = get_per_cpu_ptr(cputime);
    /* Ugh, this doesn't work: add_per_cpu(cputime.times[time], delta); */
    cpu->times[time] += delta;
}

void kcputime_get(unsigned int cpu, struct kcputime *time)
{
    struct kcputime *t = get_per_cpu_ptr_any(cputime, cpu);
    memcpy(time, t, sizeof(*t));
}
