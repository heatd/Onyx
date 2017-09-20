/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>

#include <onyx/cpu.h>
#include <onyx/rwlock.h>
#include <onyx/atomic.h>

bool rw_lock_tryread(struct rwlock *lock)
{
	unsigned long l;
	do
	{
		l = lock->lock;
		if(l == RDWR_LOCK_WRITE - 1)
			return errno = EAGAIN, false;
		if(l == RDWR_LOCK_WRITE)
			return errno = EBUSY, false;
	} while(atomic_cmp_and_swap(&lock->lock, l+1, l) != true);
	
	return true;
}

void rw_lock_read(struct rwlock *lock)
{
	while(!rw_lock_tryread(lock))
		cpu_pause();
}

void rw_lock_write(struct rwlock *lock)
{
	while(atomic_cmp_and_swap(&lock->lock, RDWR_LOCK_WRITE, 0) == false)
		cpu_pause();
}

void rw_unlock_read(struct rwlock *lock)
{
	atomic_dec(&lock->lock, 1);
}

void rw_unlock_write(struct rwlock *lock)
{
	atomic_set(&lock->lock, 0UL);
}
