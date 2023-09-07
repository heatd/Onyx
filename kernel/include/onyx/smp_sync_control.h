/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_SMP_SYNC_CONTROL_H
#define _ONYX_SMP_SYNC_CONTROL_H

#include <onyx/smp.h>
#include <onyx/wait_queue.h>

#include <onyx/atomic.hpp>
#include <onyx/tuple.hpp>

namespace smp::internal
{

struct sync_call_cntrlblk
{
    sync_call_func f;
    void *ctx;
    atomic<unsigned long> waiting_for_completion;
    unsigned int flags;
#ifdef DEBUG_SMP_SYNC_CALL
    cpumask mask;
#endif
    sync_call_cntrlblk(sync_call_func f, void *ctx, cpumask &m, unsigned int flags)
        : f{f}, ctx{ctx}, waiting_for_completion{}, flags{flags}
#ifdef DEBUG_SMP_SYNC_CALL
          ,
          mask{m}
#endif
    {
    }

    void wait(sync_call_func local, void *context2);

    void complete(unsigned int curcpu);
};

struct sync_call_elem
{
    sync_call_cntrlblk *control_block;
    struct list_head node;

    constexpr sync_call_elem(sync_call_cntrlblk *b) : control_block{b}, node{}
    {
    }
};

} // namespace smp::internal

#endif
