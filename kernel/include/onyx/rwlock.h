/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_RWLOCK_H
#define _KERNEL_RWLOCK_H

#include <onyx/compiler.h>
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
