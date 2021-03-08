/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_SEM_H
#define _ONYX_SEM_H

#ifdef __cplusplus
#include <onyx/atomic.hpp>
#endif

#include <onyx/scheduler.h>
#include <onyx/spinlock.h>

struct semaphore
{
	thread_t *head;
	thread_t *tail;
	struct spinlock lock;
#ifdef __cplusplus
	atomic<long> counter;
#else
	long counter;
#endif
};

void sem_init(struct semaphore *sem, long counter);
void sem_signal(struct semaphore *sem);
void sem_wait(struct semaphore *sem);

#endif
