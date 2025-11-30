/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_SEQLOCK_H
#define _ONYX_SEQLOCK_H

#include <onyx/seqcount.h>
#include <onyx/seqlock_types.h>
#include <onyx/spinlock.h>

static inline void write_seqlock(seqlock_t *sl)
{
    spin_lock(&sl->lock);
    write_seqcount_begin(&sl->seqcount);
}

static inline void write_sequnlock(seqlock_t *sl)
{
    write_seqcount_end(&sl->seqcount);
    spin_unlock(&sl->lock);
}

static inline unsigned int read_seqbegin(seqlock_t *sl)
{
    return read_seqcount_begin(&sl->seqcount);
}

static inline bool read_seqretry(seqlock_t *sl, unsigned int old)
{
    return !(old & 1) && read_seqcount_retry(&sl->seqcount, old);
}

static inline void read_seqbegin_or_lock(seqlock_t *sl, unsigned int *seq)
{
    if (unlikely(*seq & 1))
        spin_lock(&sl->lock);
    else
        *seq = read_seqbegin(sl);
}

static inline void done_seqretry(seqlock_t *sl, unsigned int seq)
{
    if (unlikely(seq & 1))
        spin_unlock(&sl->lock);
}

static inline void read_seqlock_excl(seqlock_t *sl)
{
    spin_lock(&sl->lock);
}

static inline void read_sequnlock_excl(seqlock_t *sl)
{
    spin_unlock(&sl->lock);
}

static inline void seqlock_init(seqlock_t *sl)
{
    seqcount_init(&sl->seqcount);
    spinlock_init(&sl->lock);
}

#endif
