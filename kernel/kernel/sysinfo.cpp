/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
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

    sys.mem_unit = PAGE_SIZE;
    page_get_stats(&memstat);
    sys.bufferram = memstat.page_cache_pages;
    sys.freehigh = 0;
    sys.freeram = memstat.total_pages - memstat.allocated_pages;
    sys.totalswap = sys.freeswap = 0;
    sys.totalram = memstat.total_pages;
    sys.totalhigh = 0;
    sys.procs = (unsigned short) process_get_active_processes();
    sys.sharedram = pagestats[NR_SHARED];

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
