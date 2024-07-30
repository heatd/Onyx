/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_SEQCOUNT_H
#define _ONYX_SEQCOUNT_H

#include <onyx/atomic.h>
#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/seqcount_types.h>

static inline void seqcount_init(seqcount_t *seq)
{
    *seq = 0;
}

static inline unsigned int read_seqcount_begin(const seqcount_t *seq)
{
    unsigned int s;
    while (unlikely((s = READ_ONCE(*seq)) & 1))
        cpu_relax();
    smp_rmb();
    return s;
}

static inline int read_seqcount_retry(const seqcount_t *seq, unsigned int old)
{
    smp_rmb();
    return unlikely(READ_ONCE(*seq) != old);
}

static inline void write_seqcount_begin(seqcount_t *seq)
{
    WRITE_ONCE(seq, seq + 1);
    smp_wmb();
}

static inline void write_seqcount_end(seqcount_t *seq)
{
    __atomic_store_n(&seq, (seq + 1), __ATOMIC_RELEASE);
}

#endif
