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
    return read_seqcount_retry(&sl->seqcount, old);
}

#endif
