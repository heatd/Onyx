/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_SPINLOCK_H
#define _KERNEL_SPINLOCK_H

#include <stdbool.h>

struct spinlock
{
	unsigned long lock;
	unsigned long waiters;
	unsigned long holder;
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
#ifdef __cplusplus
}
#endif
#endif
