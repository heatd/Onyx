/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _KTSAN_INTERNAL_SPINLOCK_H
#define _KTSAN_INTERNAL_SPINLOCK_H

#include <onyx/compiler.h>
#include <onyx/preempt.h>

// TODO: TSAN has its own sanitizer_common Mutex implementation. google KTSAN has its own
// kt_spinlock. Why can't they call the normal mutex/spinlock stuff? weird. Investigate? Compare
// performance?

#if 0
/* KTSAN needs a custom spinlock implementation that is not instrumented by TSAN itself.
 * If we were to use the normal spinlocks in e.g an acquire operation, we would end up recursing.
 */

struct kt_spinlock
{
    unsigned int lock;
};
#else
#include <onyx/spinlock.h>
using kt_spinlock = spinlock;
#define kt_spin_lock   spin_lock
#define kt_spin_unlock spin_unlock
#endif

#endif
