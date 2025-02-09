/*
 * Copyright (c) 2024 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_ATOMIC_H
#define _ONYX_ATOMIC_H

#include <platform/atomic.h>

#define READ_ONCE(var)       (__atomic_load_n(&(var), __ATOMIC_RELAXED))
#define WRITE_ONCE(var, val) (__atomic_store_n(&(var), (val), __ATOMIC_RELAXED))

#define atomic_and_relaxed(var, mask) (__atomic_and_fetch(&(var), mask, __ATOMIC_RELAXED))
#define atomic_or_relaxed(var, mask)  (__atomic_or_fetch(&(var), mask, __ATOMIC_RELAXED))

#ifdef __cplusplus
#define __auto_type auto
#endif

#define cmpxchg(ptr, old, new)                                                                    \
    ({                                                                                            \
        __auto_type __old = (old);                                                                \
        __atomic_compare_exchange_n(ptr, &__old, new, false, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED); \
        __old;                                                                                    \
    })

#define cmpxchg_relaxed(ptr, old, new)                                                            \
    ({                                                                                            \
        __auto_type __old = (old);                                                                \
        __atomic_compare_exchange_n(ptr, &__old, new, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED); \
        __old;                                                                                    \
    })

#ifndef smp_store_mb
#define smp_store_mb(var, value) \
    do                           \
    {                            \
        WRITE_ONCE(var, value);  \
        smp_mb();                \
    } while (0)
#endif

#ifndef smp_mb__before_atomic
#define smp_mb__before_atomic() smp_mb()
#endif

#ifndef smp_mb__after_atomic
#define smp_mb__after_atomic() smp_mb()
#endif

#ifndef smp_mb__after_spinlock
#define smp_mb__after_spinlock() smp_mb()
#endif

#endif
