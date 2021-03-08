/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <assert.h>

#include <onyx/spinlock.h>
#include <onyx/compiler.h>
#include <onyx/task_switching.h>
#include <onyx/scheduler.h>
#include <onyx/cpu.h>

__attribute__((always_inline))
static inline void post_lock_actions(struct spinlock *lock)
{
#ifdef CONFIG_SPINLOCK_DEBUG
	lock->holder = (unsigned long) __builtin_return_address(1);
#endif
}

static inline void post_release_actions(struct spinlock *lock)
{
#ifdef CONFIG_SPINLOCK_DEBUG
	lock->holder = 0xDEADBEEFDEADBEEF;
#endif
}


void spin_lock_preempt(struct spinlock *lock)
{
	raw_spinlock_t expected_val = 0;
	raw_spinlock_t what_to_insert = get_cpu_nr() + 1;

	while(true)
	{
		while(__atomic_load_n(&lock->lock, __ATOMIC_RELAXED) != 0)
			cpu_relax();

		expected_val = 0;
		
		if(__atomic_compare_exchange_n(&lock->lock, &expected_val, what_to_insert,
		                               false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
			break;
	}

	post_lock_actions(lock);
}

void spin_unlock_preempt(struct spinlock *lock)
{
#ifdef CONFIG_SPINLOCK_DEBUG
	assert(lock->lock > 0);
#endif

	post_release_actions(lock);

	__atomic_store_n(&lock->lock, 0, __ATOMIC_RELEASE);
}

void spin_lock(struct spinlock *lock)
{
	sched_disable_preempt();

	spin_lock_preempt(lock);
	post_lock_actions(lock);
}

void spin_unlock(struct spinlock *lock)
{
	spin_unlock_preempt(lock);
	sched_enable_preempt();
}

int spin_try_lock(struct spinlock *lock)
{

	/* Disable preemption before locking, and enable it on release.
	 * This means locks get faster
	*/
	sched_disable_preempt();

	raw_spinlock_t expected_val = 0;
	raw_spinlock_t what_to_insert = get_cpu_nr() + 1;


	if(!__atomic_compare_exchange_n(&lock->lock, &expected_val, what_to_insert,
		                               false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
	{
		sched_enable_preempt();
		return 1;
	}

	post_lock_actions(lock);
	return 0;
}
