/*----------------------------------------------------------------------
 * Copyright (C) 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _KERNEL_RWLOCK_H
#define _KERNEL_RWLOCK_H

#include <kernel/compiler.h>
struct rwlock	
{
	unsigned long lock;
	unsigned long rw;
	unsigned long readers __align_cache; /* We're aligning these four, to minimize cache line bouncing */
	unsigned long writers __align_cache;
};

void rw_lock_read(struct rwlock *lock);
void rw_lock_write(struct rwlock *lock);
void rw_unlock_read(struct rwlock *lock);
void rw_unlock_write(struct rwlock *lock);
#endif