/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_SPINLOCK_H
#define _KERNEL_SPINLOCK_H
#include <stdbool.h>

typedef struct spinlock
{
	unsigned long lock;
	unsigned long waiters;
	bool old_preemption_state; /* This lets us nest locks */
	unsigned long holder;
} spinlock_t;
#ifdef __cplusplus
extern "C" {
#endif
void acquire_spinlock(spinlock_t *lock);
void release_spinlock(spinlock_t *lock);
int try_and_acquire_spinlock(spinlock_t *lock);
void wait_spinlock(spinlock_t*);
#ifdef __cplusplus
}
#endif
#endif
