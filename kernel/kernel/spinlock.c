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
#include <onyx/atomic.h>
#include <onyx/cpu.h>

static inline void post_lock_actions(spinlock_t *lock)
{
	lock->old_preemption_state = sched_is_preemption_disabled();
	/* Disable preemption after locking, and enable it on release. This means locks get faster */
	sched_change_preemption_state(true);
	lock->holder = (unsigned long) __builtin_return_address(0);
}

static inline void post_release_actions(spinlock_t *lock)
{
	sched_change_preemption_state(lock->old_preemption_state);
	lock->holder = 0xDEADBEEFDEADBEEF;
}

void acquire_spinlock(spinlock_t *lock)
{
	while(!__sync_bool_compare_and_swap(&lock->lock, 0, 1))
	{
		cpu_pause();
	}
	__sync_synchronize();
	post_lock_actions(lock);
}

void release_spinlock(spinlock_t *lock)
{
	__sync_synchronize();

#ifdef CONFIG_SPINLOCK_DEBUG
	assert(lock->lock > 0);
#endif
	atomic_dec(&lock->lock, 1);
	post_release_actions(lock);
}

int try_and_acquire_spinlock(spinlock_t *lock)
{
	while(!__sync_bool_compare_and_swap(&lock->lock, 0, 1))
	{
		return 1;
	}
	__sync_synchronize();
	post_lock_actions(lock);
	return 0;
}
