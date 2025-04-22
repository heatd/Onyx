/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/cputime.h>
#include <onyx/irq.h>
#include <onyx/proc.h>
#include <onyx/process.h>
#include <onyx/scheduler.h>
#include <onyx/seq_file.h>

static __clock_t nsec_to_clock_t(hrtime_t time)
{
    return time / NS_PER_MS;
}

static int proc_stat_show(struct seq_file *m, void *ptr)
{
    struct kcputime time = {};
    for (unsigned int i = 0; i < get_nr_cpus(); i++)
    {
        struct kcputime cpu;
        kcputime_get(i, &cpu);
        for (unsigned int j = 0; j < CPUTIME_MAX; j++)
            time.times[j] += cpu.times[j];
    }

    seq_printf(
        m, "cpu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
        nsec_to_clock_t(time.times[CPUTIME_USER]), nsec_to_clock_t(time.times[CPUTIME_NICE]),
        nsec_to_clock_t(time.times[CPUTIME_SYSTEM]), nsec_to_clock_t(time.times[CPUTIME_IDLE]),
        nsec_to_clock_t(time.times[CPUTIME_IOWAIT]), nsec_to_clock_t(time.times[CPUTIME_IRQ]),
        nsec_to_clock_t(time.times[CPUTIME_SOFTIRQ]), nsec_to_clock_t(time.times[CPUTIME_STEAL]),
        nsec_to_clock_t(time.times[CPUTIME_GUEST]),
        nsec_to_clock_t(time.times[CPUTIME_GUEST_NICE]));

    for (unsigned int i = 0; i < get_nr_cpus(); i++)
    {
        kcputime_get(i, &time);
        seq_printf(
            m, "cpu%d: %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n", i,
            nsec_to_clock_t(time.times[CPUTIME_USER]), nsec_to_clock_t(time.times[CPUTIME_NICE]),
            nsec_to_clock_t(time.times[CPUTIME_SYSTEM]), nsec_to_clock_t(time.times[CPUTIME_IDLE]),
            nsec_to_clock_t(time.times[CPUTIME_IOWAIT]), nsec_to_clock_t(time.times[CPUTIME_IRQ]),
            nsec_to_clock_t(time.times[CPUTIME_SOFTIRQ]),
            nsec_to_clock_t(time.times[CPUTIME_STEAL]), nsec_to_clock_t(time.times[CPUTIME_GUEST]),
            nsec_to_clock_t(time.times[CPUTIME_GUEST_NICE]));
    }

    irq_print_stat(m);
    seq_printf(m, "ctxt %lu\n", sched_total_ctx_switches());
    seq_printf(m, "btime %lu\n", clocksource_get_time() / NS_PER_SEC);
    seq_printf(m, "processes %lu\n", get_forks_since_boot());
    seq_printf(m, "procs_running %lu\n", sched_get_runnable());
    seq_printf(m, "procs_blocked 0\n");
    return 0;
}

static int proc_stat_open(struct file *filp)
{
    return single_open(filp, proc_stat_show, NULL);
}

static const struct proc_file_ops proc_stat_ops = {
    .open = proc_stat_open,
    .read_iter = seq_read_iter,
    .release = seq_release,
};

static __init void proc_stat_init(void)
{
    procfs_add_entry("stat", 0444, NULL, &proc_stat_ops);
}
