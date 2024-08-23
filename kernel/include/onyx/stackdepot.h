/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_STACKDEPOT_H
#define _ONYX_STACKDEPOT_H

#include <onyx/compiler.h>
#include <onyx/types.h>

typedef u32 depot_stack_handle_t;

#define DEPOT_STACK_HANDLE_INVALID 0

struct stacktrace
{
    u32 hash;
    u32 size;
    depot_stack_handle_t handle;
    struct stacktrace *next;
    unsigned long entries[];
};

__BEGIN_CDECLS

depot_stack_handle_t stackdepot_save_stack(unsigned long *entries, unsigned long nr_entries);
struct stacktrace *stackdepot_from_handle(depot_stack_handle_t handle);

__END_CDECLS

#endif
