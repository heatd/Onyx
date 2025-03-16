/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <sys/sysinfo.h>

#include <onyx/page.h>
#include <onyx/process.h>

#include <uapi/memstat.h>

extern unsigned long avenrun[3];

struct sysinfo do_sys_sysinfo()
{
    struct sysinfo sys;
    struct memstat memstat;
    struct timespec boottime;
    unsigned long pagestats[PAGE_STATS_MAX];
    page_accumulate_stats(pagestats);

    /* Using mem_unit = PAGE_SIZE sounds obvious, but Linux advertises mem_unit = 1 and some
     * userspace (e.g toybox top) seems to assume that. */
    sys.mem_unit = 1;
    page_get_stats(&memstat);
    sys.bufferram = memstat.page_cache_pages << PAGE_SHIFT;
    sys.freehigh = 0;
    sys.freeram = (memstat.total_pages - memstat.allocated_pages) << PAGE_SHIFT;
    sys.totalswap = sys.freeswap = 0;
    sys.totalram = memstat.total_pages << PAGE_SHIFT;
    sys.totalhigh = 0;
    sys.procs = (unsigned short) process_get_active_processes();
    sys.sharedram = pagestats[NR_SHARED] << PAGE_SHIFT;

    if (clock_gettime_kernel(CLOCK_BOOTTIME, &boottime) < 0)
    {
        sys.uptime = 0;
    }
    else
    {
        sys.uptime = boottime.tv_sec;
    }

    for (int i = 0; i < 3; i++)
    {
        sys.loads[i] = avenrun[i] << (SI_LOAD_SHIFT - 11);
    }

    return sys;
}

int sys_sysinfo(struct sysinfo *usysinfo)
{
    struct sysinfo sys = do_sys_sysinfo();

    if (copy_to_user(usysinfo, &sys, sizeof(struct sysinfo)) < 0)
        return -EFAULT;
    return 0;
}
