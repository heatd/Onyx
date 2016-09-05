/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <kernel/spinlock.h>
#include <stdio.h>
#include <kernel/compiler.h>
void acquire_spinlock(spinlock_t *lock)
{
	mutex_lock(&lock->lock);
}

void release_spinlock(spinlock_t *lock)
{
	mutex_unlock(&lock->lock);
}

void wait_spinlock(spinlock_t *lock)
{
	while (lock->lock == 1);
}
