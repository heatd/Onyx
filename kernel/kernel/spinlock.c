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

void spinlock_lock(unsigned long *);
void spinlock_unlock(unsigned long *);
void acquire_spinlock(spinlock_t *lock)
{
	spinlock_lock(&lock->lock);
	lock->old_preemption_state = sched_is_preemption_disabled();
	/* Disable preemption after locking, and enable it on release. This means locks get faster */
	sched_change_preemption_state(true);
}

void release_spinlock(spinlock_t *lock)
{
	spinlock_unlock(&lock->lock);
	sched_change_preemption_state(lock->old_preemption_state);
}
void wait_spinlock(spinlock_t *lock)
{
	while (lock->lock == 1);
}
void acquire_critical_lock(spinlock_t *critical_lock)
{
	unsigned long l = __sync_add_and_fetch(&critical_lock->waiters, 1);
	if(l > 1)
		sched_yield();
	spinlock_lock(&critical_lock->lock);
	__sync_sub_and_fetch(&critical_lock->waiters, 1);
}
void release_critical_lock(spinlock_t *critical_lock)
{
	spinlock_unlock(&critical_lock->lock);
	sched_yield();
}
