/*
 * Copyright (c) 2016 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <assert.h>
#include <stdio.h>

#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/scheduler.h>
#include <onyx/spinlock.h>
#include <onyx/task_switching.h>

#include <linux/lockdep.h>

static __always_inline void post_lock_actions(struct spinlock *lock)
{
#ifdef CONFIG_SPINLOCK_DEBUG
    lock->holder = (unsigned long) __builtin_return_address(1);
#endif
}

static __always_inline void post_release_actions(struct spinlock *lock)
{
#ifdef CONFIG_SPINLOCK_DEBUG
    lock->holder = 0xDEADBEEFDEADBEEF;
#endif
}

static __always_inline bool arch_spin_lock_fast_path(arch_spinlock_t *lock,
                                                     arch_spinlock_t cpu_nr_plus_one)
{
    arch_spinlock_t expected_val = ARCH_SPIN_LOCK_UNLOCKED;
    return __atomic_compare_exchange_n(&lock->lock, &expected_val.lock, cpu_nr_plus_one.lock, false,
                                       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

__noinline void arch_spin_lock_slow_path(arch_spinlock_t *lock, arch_spinlock_t what_to_insert)
{
    arch_spinlock_t expected_val = ARCH_SPIN_LOCK_UNLOCKED;

    while (true)
    {
        do
        {
            cpu_relax();
        } while (__atomic_load_n(&lock->lock, __ATOMIC_RELAXED) != 0);

        if (__atomic_compare_exchange_n(&lock->lock, &expected_val.lock, what_to_insert.lock, false,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            break;

        expected_val = ARCH_SPIN_LOCK_UNLOCKED;
    }
}

void arch_spin_lock(arch_spinlock_t *lock)
{
    arch_spinlock_t what_to_insert = {.lock = get_cpu_nr() + 1};
    if (!arch_spin_lock_fast_path(lock, what_to_insert)) [[unlikely]]
        arch_spin_lock_slow_path(lock, what_to_insert);
}

void __spin_lock(struct spinlock *lock)
{
    spin_acquire(&lock->dep_map, 0, 0, _RET_IP_);
    arch_spin_lock(&lock->lock);
    post_lock_actions(lock);
}

void arch_spin_unlock(arch_spinlock_t *lock)
{
    __atomic_store_n(&lock->lock, 0, __ATOMIC_RELEASE);
}

void __spin_unlock(struct spinlock *lock)
{
#ifdef CONFIG_SPINLOCK_DEBUG
    assert(lock->lock > 0);
#endif

    post_release_actions(lock);
    spin_release(&lock->dep_map, _RET_IP_);
    arch_spin_unlock(&lock->lock);
}

int arch_spin_trylock(arch_spinlock_t *lock)
{
    arch_spinlock_t expected_val = ARCH_SPIN_LOCK_UNLOCKED;
    arch_spinlock_t what_to_insert = {.lock = get_cpu_nr() + 1};

    if (!__atomic_compare_exchange_n(&lock->lock, &expected_val.lock, what_to_insert.lock, false,
                                     __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return 1;
    return 0;
}

int spin_try_lock(struct spinlock *lock)
{
    sched_disable_preempt();

    if (arch_spin_trylock(&lock->lock))
    {
        sched_enable_preempt();
        return 1;
    }

    spin_acquire(&lock->dep_map, 0, 1, _RET_IP_);
    post_lock_actions(lock);
    return 0;
}

#ifdef CONFIG_LOCKDEP
void spinlock_init_lockdep(struct spinlock *lock, const char *name, struct lock_class_key *key)
{
    lockdep_init_map_wait(&lock->dep_map, name, key, 0, LD_WAIT_CONFIG);
}
#endif
