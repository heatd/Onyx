/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define smp_wmb() __asm__ __volatile__("" ::: "memory")
#define smp_rmb() __asm__ __volatile__("" ::: "memory")
#define smp_mb()  __asm__ __volatile__("lock addl $0, -4(%%rsp)" ::: "memory", "cc")

#define __x86_xchg(ptr, val)                                                       \
    ({                                                                             \
        __typeof__(*(ptr)) v = val;                                                \
        __asm__ __volatile__("xchg %0, %1" : "+r"(v), "+m"(*ptr)::"memory", "cc"); \
        v;                                                                         \
    })

/* x86 atomic ops imply a full memory barrier. xchg is implicitly an atomic op (with an implicit
 * LOCK prefix too). This is more efficient than doing WRITE_ONCE + smp_mb. */
#define smp_store_mb(ptr, val) __x86_xchg(ptr, val)

/* every smp_mb around atomics (including spinlock, which involved atomics itself) can be elided */
/* clang-format off */
#define smp_mb__before_atomic() do {} while (0)
#define smp_mb__after_atomic() do {} while (0)
#define smp_mb__after_spinlock() do {} while (0)
/* clang-format on */
