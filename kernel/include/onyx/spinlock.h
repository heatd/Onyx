/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_SPINLOCK_H
#define _KERNEL_SPINLOCK_H

#include <stdbool.h>

#include <onyx/x86/irq.h>

struct spinlock
{
	unsigned long lock;
	unsigned long waiters;
	unsigned long holder;
	unsigned long old_flags;
};

#ifdef __cplusplus
extern "C" {
#endif


void spin_lock(struct spinlock *lock);
void spin_unlock(struct spinlock *lock);
void spin_lock_preempt(struct spinlock *lock);
void spin_unlock_preempt(struct spinlock *lock);
int try_and_spin_lock(struct spinlock *lock);
void wait_spinlock(struct spinlock*);


static inline void spin_lock_irqsave(struct spinlock *lock)
{
	unsigned long flags = irq_save_and_disable();
	spin_lock_preempt(lock);
	lock->old_flags = flags;
}

static inline void spin_unlock_irqrestore(struct spinlock *lock)
{
	spin_unlock_preempt(lock);
	irq_restore(lock->old_flags);
}

#ifdef __cplusplus
}
#endif
#endif
