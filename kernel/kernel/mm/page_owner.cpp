/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/page.h>
#include <onyx/perf_probe.h>
#include <onyx/stackdepot.h>

#define PAGE_OWNER_STACK_DEPTH 16

void page_owner_owned(struct page *p)
{
    unsigned long trace[PAGE_OWNER_STACK_DEPTH];
    unsigned long nr = stack_trace_get((unsigned long *) __builtin_frame_address(0), trace,
                                       PAGE_OWNER_STACK_DEPTH);
    p->last_owner = stackdepot_save_stack(trace, nr);
}

void page_owner_freed(struct page *p)
{
    unsigned long trace[PAGE_OWNER_STACK_DEPTH];
    unsigned long nr = stack_trace_get((unsigned long *) __builtin_frame_address(0), trace,
                                       PAGE_OWNER_STACK_DEPTH);
    p->last_free = stackdepot_save_stack(trace, nr);
}

void page_owner_locked(struct page *p)
{
    unsigned long trace[PAGE_OWNER_STACK_DEPTH];
    unsigned long nr = stack_trace_get((unsigned long *) __builtin_frame_address(0), trace,
                                       PAGE_OWNER_STACK_DEPTH);

    p->last_lock = stackdepot_save_stack(trace, nr);
}

void page_owner_unlocked(struct page *p)
{
    unsigned long trace[PAGE_OWNER_STACK_DEPTH];
    unsigned long nr = stack_trace_get((unsigned long *) __builtin_frame_address(0), trace,
                                       PAGE_OWNER_STACK_DEPTH);

    p->last_unlock = stackdepot_save_stack(trace, nr);
}
