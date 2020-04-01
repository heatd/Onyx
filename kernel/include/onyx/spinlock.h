/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_SPINLOCK_H
#define _KERNEL_SPINLOCK_H

#include <stdbool.h>
#include <assert.h>

#include <onyx/smp.h>
#include <onyx/x86/irq.h>

struct spinlock
{
	unsigned long lock;
	unsigned long waiters;
	unsigned long holder;
	unsigned long owner_cpu;
	unsigned long old_flags;
};

#ifdef __cplusplus
extern "C" {
#endif


void spin_lock(struct spinlock *lock);
void spin_unlock(struct spinlock *lock);
void spin_lock_preempt(struct spinlock *lock);
void spin_unlock_preempt(struct spinlock *lock);
int spin_try_lock(struct spinlock *lock);
void wait_spinlock(struct spinlock*);


static inline void spin_lock_irqsave(struct spinlock *lock)
{
	unsigned long flags = irq_save_and_disable();
	spin_lock_preempt(lock);
	lock->old_flags = flags;
}

static inline void spin_unlock_irqrestore(struct spinlock *lock)
{
	unsigned long old = lock->old_flags;
	spin_unlock_preempt(lock);
	irq_restore(old);
}

static inline bool spin_lock_held(struct spinlock *lock)
{
	return lock->lock == 1 && lock->owner_cpu == (unsigned long) get_cpu_nr();
}

#define MUST_HOLD_LOCK(lock)		assert(spin_lock_held(lock) != false)

#ifdef __cplusplus
}

class Spinlock
{
private:
	struct spinlock lock;
public:
	constexpr Spinlock() : lock {} {};
	~Spinlock()
	{
		assert(lock.lock != 1);
	}
	void Lock()
	{
		spin_lock(&lock);
	}

	void LockIrqsave()
	{
		spin_lock_irqsave(&lock);
	}

	void Unlock()
	{
		spin_unlock(&lock);
	}

	void UnlockIrqrestore()
	{
		spin_unlock_irqrestore(&lock);
	}

	bool IsLocked()
	{
		return lock.lock == 1;
	}
};






#endif
#endif
