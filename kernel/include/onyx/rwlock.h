/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_RWLOCK_H
#define _KERNEL_RWLOCK_H

#include <onyx/compiler.h>
#include <onyx/spinlock.h>

#define RDWR_LOCK_WRITE			0x7fffffff

struct rwlock
{
	unsigned long lock;
	struct thread *head, *tail;
	struct spinlock llock;
};

#ifdef __cplusplus
extern "C" {
#endif

bool rw_lock_tryread(struct rwlock *lock);
void rw_lock_read(struct rwlock *lock);
void rw_lock_write(struct rwlock *lock);
int rw_lock_write_interruptible(struct rwlock *lock);
int rw_lock_read_interruptible(struct rwlock *lock);
void rw_unlock_read(struct rwlock *lock);
void rw_unlock_write(struct rwlock *lock);

static inline void rwlock_init(struct rwlock *lock)
{
	lock->lock = 0;
	lock->head = lock->tail = NULL;
	spinlock_init(&lock->llock);
}

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

enum class rw_lock
{
	read = 0,
	write
};

template <rw_lock lock_type>
class scoped_rwlock
{
private:
	bool IsLocked;
	rwlock& internal_lock;
public:

	constexpr bool read() const
	{
		return lock_type == rw_lock::read;
	}

	constexpr bool write() const
	{
		return lock_type == rw_lock::write;
	}

	void lock()
	{
		if(read())
			rw_lock_read(&internal_lock);
		else
			rw_lock_write(&internal_lock);
		IsLocked = true;
	}

	void unlock()
	{
		if(read())
			rw_unlock_read(&internal_lock);
		else
			rw_unlock_write(&internal_lock);
		IsLocked = false;
	}

	scoped_rwlock(rwlock& lock) : internal_lock(lock)
	{
		this->lock();
	}

	~scoped_rwlock()
	{
		if(IsLocked)
			unlock();
	}
};

#endif

#endif
