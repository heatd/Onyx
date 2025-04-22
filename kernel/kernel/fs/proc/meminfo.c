/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/page.h>
#include <onyx/proc.h>
#include <onyx/seq_file.h>
#include <onyx/swap.h>

#include <uapi/memstat.h>

static int proc_meminfo_show(struct seq_file *m, void *ptr)
{
    struct memstat memstat;
    unsigned long pagestats[PAGE_STATS_MAX];
    unsigned long free;
    page_accumulate_stats(pagestats);
    page_get_stats(&memstat);

    free = memstat.total_pages - memstat.allocated_pages;

#define PGTOKB(pages) ((pages) << (PAGE_SHIFT - 10))

    seq_printf(m, "MemTotal: %lu kB\n", PGTOKB(memstat.total_pages));
    seq_printf(m, "MemFree: %lu kB\n", PGTOKB(free));
    seq_printf(m, "MemAvailable: %lu kB\n",
               PGTOKB(free + pagestats[NR_FILE] + pagestats[NR_SLAB_RECLAIMABLE]));
    seq_printf(m, "Buffers: 0 kB\n");
    seq_printf(m, "Cached: %lu kB\n", PGTOKB(memstat.page_cache_pages));
    seq_printf(m, "SwapCached: 0 kB\n");
    seq_printf(m, "Active: %lu kB\n",
               PGTOKB(pagestats[NR_ACTIVE_FILE] + pagestats[NR_ACTIVE_ANON]));
    seq_printf(m, "Inactive: %lu kB\n",
               PGTOKB(pagestats[NR_INACTIVE_FILE] + pagestats[NR_INACTIVE_ANON]));
    seq_printf(m, "Active(anon): %lu kB\n", PGTOKB(pagestats[NR_ACTIVE_ANON]));
    seq_printf(m, "Inactive(anon): %lu kB\n", PGTOKB(pagestats[NR_INACTIVE_ANON]));
    seq_printf(m, "Active(file): %lu kB\n", PGTOKB(pagestats[NR_ACTIVE_FILE]));
    seq_printf(m, "Inactive(file): %lu kB\n", PGTOKB(pagestats[NR_INACTIVE_FILE]));
    seq_printf(m, "Unevictable: 0 kB\n");
    seq_printf(m, "Mlocked: 0 kB\n");
    seq_printf(m, "HighTotal: 0 kB\n");
    seq_printf(m, "LowTotal: %lu kB\n", PGTOKB(memstat.total_pages));
    seq_printf(m, "LowFree: %lu kB\n", PGTOKB(free));
    seq_printf(m, "SwapTotal: %lu kB\n", PGTOKB(swap_total()));
    seq_printf(m, "SwapTotal: %lu kB\n", PGTOKB(swap_free()));
    seq_printf(m, "Dirty: %lu kB\n", PGTOKB(pagestats[NR_DIRTY]));
    seq_printf(m, "Writeback: %lu kB\n", PGTOKB(pagestats[NR_WRITEBACK]));
    seq_printf(m, "AnonPages: %lu kB\n", PGTOKB(pagestats[NR_ANON]));
    /* TODO: Mapped is always 0 (Need NR_FILE_MAPPED maintenance) */
    seq_printf(m, "Mapped: %lu kB\n", PGTOKB(pagestats[NR_FILE_MAPPED]));
    seq_printf(m, "Shmem: %lu kB\n", PGTOKB(pagestats[NR_SHARED]));
    seq_printf(m, "KReclaimable: %lu kB\n", PGTOKB(pagestats[NR_SLAB_RECLAIMABLE]));
    seq_printf(m, "Slab: %lu kB\n",
               PGTOKB(pagestats[NR_SLAB_RECLAIMABLE] + pagestats[NR_SLAB_UNRECLAIMABLE]));
    seq_printf(m, "SReclaimable: %lu kB\n", PGTOKB(pagestats[NR_SLAB_RECLAIMABLE]));
    seq_printf(m, "SUnreclaim: %lu kB\n", PGTOKB(pagestats[NR_SLAB_UNRECLAIMABLE]));
    seq_printf(m, "KernelStack: %lu kB\n", PGTOKB(pagestats[NR_KSTACK]));
    seq_printf(m, "PageTables: %lu kB\n", PGTOKB(pagestats[NR_PTES]));
    return 0;
}

static int proc_meminfo_open(struct file *filp)
{
    return single_open(filp, proc_meminfo_show, NULL);
}

static const struct proc_file_ops proc_meminfo_ops = {
    .open = proc_meminfo_open,
    .read_iter = seq_read_iter,
    .release = seq_release,
};

static __init void proc_meminfo_init(void)
{
    procfs_add_entry("meminfo", 0444, NULL, &proc_meminfo_ops);
}
