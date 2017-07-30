/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>

#include <kernel/spinlock.h>
#include <kernel/compiler.h>
#include <kernel/task_switching.h>
#include <kernel/scheduler.h>

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
		__asm__ __volatile__("pause");
	}
	__sync_synchronize();
	post_lock_actions(lock);
}

void release_spinlock(spinlock_t *lock)
{
	__sync_synchronize();
	lock->lock = 0;
	post_release_actions(lock);
}
void wait_spinlock(spinlock_t *lock)
{
	while (lock->lock == 1);
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
