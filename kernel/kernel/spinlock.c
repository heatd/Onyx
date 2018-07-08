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

static inline void post_lock_actions(struct spinlock *lock)
{
	lock->holder = (unsigned long) __builtin_return_address(0);
}

static inline void post_release_actions(struct spinlock *lock)
{
	lock->holder = 0xDEADBEEFDEADBEEF;
}


void spin_lock_preempt(struct spinlock *lock)
{
	while(!__sync_bool_compare_and_swap(&lock->lock, 0, 1))
	{
		cpu_pause();
	}
	__sync_synchronize();
}

void spin_unlock_preempt(struct spinlock *lock)
{
	__sync_synchronize();

	assert(lock->lock > 0);

	atomic_dec(&lock->lock, 1);
	post_release_actions(lock);
}

void spin_lock(struct spinlock *lock)
{
	spin_lock_preempt(lock);
	post_lock_actions(lock);

	/* Disable preemption before locking, and enable it on release.
	 * This means locks get faster
	*/
	sched_disable_preempt();
}

void spin_unlock(struct spinlock *lock)
{
	spin_unlock_preempt(lock);
	sched_enable_preempt();
}

int try_and_spin_lock(struct spinlock *lock)
{

	/* Disable preemption before locking, and enable it on release.
	 * This means locks get faster
	*/
	sched_disable_preempt();

	while(!__sync_bool_compare_and_swap(&lock->lock, 0, 1))
	{
		sched_enable_preempt();
		return 1;
	}

	__sync_synchronize();
	post_lock_actions(lock);
	return 0;
}
