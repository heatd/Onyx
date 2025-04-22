/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/cpu.h>
#include <onyx/cputime.h>
#include <onyx/proc.h>
#include <onyx/scheduler.h>
#include <onyx/seq_file.h>

static int proc_uptime_show(struct seq_file *m, void *ptr)
{
    struct kcputime time = {};
    for (unsigned int i = 0; i < get_nr_cpus(); i++)
    {
        struct kcputime cpu;
        kcputime_get(i, &cpu);
        for (unsigned int j = 0; j < CPUTIME_MAX; j++)
            time.times[j] += cpu.times[j];
    }

    seq_printf(m, "%lu %lu\n", clocksource_get_time() / NS_PER_SEC,
               time.times[CPUTIME_IDLE] / NS_PER_SEC);
    return 0;
}

static int proc_uptime_open(struct file *filp)
{
    return single_open(filp, proc_uptime_show, NULL);
}

static const struct proc_file_ops proc_uptime_ops = {
    .open = proc_uptime_open,
    .read_iter = seq_read_iter,
    .release = seq_release,
};

static __init void proc_uptime_init(void)
{
    procfs_add_entry("uptime", 0444, NULL, &proc_uptime_ops);
}
