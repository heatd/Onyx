/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <stdio.h>

#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/scheduler.h>
#include <onyx/spinlock.h>
#include <onyx/task_switching.h>

__always_inline void post_lock_actions(struct spinlock *lock)
{
#ifdef CONFIG_SPINLOCK_DEBUG
    lock->holder = (unsigned long) __builtin_return_address(1);
#endif
}

__always_inline void post_release_actions(struct spinlock *lock)
{
#ifdef CONFIG_SPINLOCK_DEBUG
    lock->holder = 0xDEADBEEFDEADBEEF;
#endif
}

__always_inline bool spin_lock_fast_path(struct spinlock *lock, raw_spinlock_t cpu_nr_plus_one)
{
    raw_spinlock_t expected_val = 0;
    return __atomic_compare_exchange_n(&lock->lock, &expected_val, cpu_nr_plus_one, false,
                                       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

__noinline void spin_lock_slow_path(struct spinlock *lock, raw_spinlock_t what_to_insert)
{
    raw_spinlock_t expected_val = 0;

    while (true)
    {
        do
        {
            cpu_relax();
        } while (__atomic_load_n(&lock->lock, __ATOMIC_RELAXED) != 0);

        if (__atomic_compare_exchange_n(&lock->lock, &expected_val, what_to_insert, false,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            break;

        expected_val = 0;
    }
}

void __spin_lock(struct spinlock *lock)
{
    raw_spinlock_t what_to_insert = get_cpu_nr() + 1;
    if (!spin_lock_fast_path(lock, what_to_insert)) [[unlikely]]
        spin_lock_slow_path(lock, what_to_insert);

    post_lock_actions(lock);
}

void __spin_unlock(struct spinlock *lock)
{
#ifdef CONFIG_SPINLOCK_DEBUG
    assert(lock->lock > 0);
#endif

    post_release_actions(lock);

    __atomic_store_n(&lock->lock, 0, __ATOMIC_RELEASE);
}

int spin_try_lock(struct spinlock *lock)
{
    sched_disable_preempt();

    raw_spinlock_t expected_val = 0;
    raw_spinlock_t what_to_insert = get_cpu_nr() + 1;

    if (!__atomic_compare_exchange_n(&lock->lock, &expected_val, what_to_insert, false,
                                     __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
    {
        sched_enable_preempt();
        return 1;
    }

    post_lock_actions(lock);
    return 0;
}
