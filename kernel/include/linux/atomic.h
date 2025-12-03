/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 license.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _LINUX_ATOMIC_H
#define _LINUX_ATOMIC_H

#include <linux/types.h>

static inline int atomic_read(atomic_t *v)
{
    return READ_ONCE(v->counter);
}

#define xchg(ptr, v) __atomic_exchange_n(ptr, v, __ATOMIC_SEQ_CST)
#define try_cmpxchg(ptr, old, new) __atomic_compare_exchange_n(ptr, old, new, true, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED)

#endif
