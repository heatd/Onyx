/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_SEQLOCK_TYPES_H
#define _ONYX_SEQLOCK_TYPES_H

#include <onyx/seqcount_types.h>
#include <onyx/spinlock.h>

typedef struct seqlock
{
    struct spinlock lock;
    seqcount_t seqcount;
} seqlock_t;

#endif
