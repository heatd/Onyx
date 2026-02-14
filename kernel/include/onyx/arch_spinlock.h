/*
 * Copyright (c) 2016 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_ARCH_SPINLOCK_H
#define _ONYX_ARCH_SPINLOCK_H

#include <onyx/atomic.h>
#include <onyx/compiler.h>

typedef struct arch_spinlock
{
    unsigned int lock;
} arch_spinlock_t;

__BEGIN_CDECLS

void arch_spin_lock(arch_spinlock_t *lock);
void arch_spin_unlock(arch_spinlock_t *lock);
int arch_spin_trylock(arch_spinlock_t *lock);

__END_CDECLS

// clang-format off
#define __ARCH_SPIN_LOCK_UNLOCKED {}
#define ARCH_SPIN_LOCK_UNLOCKED (arch_spinlock_t) __ARCH_SPIN_LOCK_UNLOCKED
// clang-format on

#endif
