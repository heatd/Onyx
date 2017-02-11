/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdio.h>

#include <kernel/spinlock.h>
#include <kernel/compiler.h>
#include <kernel/task_switching.h>
void spinlock_lock(unsigned long *);
void spinlock_unlock(unsigned long *);
void acquire_spinlock(spinlock_t *lock)
{
	spinlock_lock(&lock->lock);
}

void release_spinlock(spinlock_t *lock)
{
	spinlock_unlock(&lock->lock);
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
