/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_SEM_H
#define _ONYX_SEM_H
#include <stdatomic.h>

#include <onyx/scheduler.h>
#include <onyx/spinlock.h>

struct semaphore
{
	thread_t *head;
	thread_t *tail;
	struct spinlock llock;
	struct spinlock bin_sem;
#ifndef __cplusplus
	atomic_long counter;
#else
	long counter;
#endif
};

void sem_init(struct semaphore *sem, long counter);
void sem_signal(struct semaphore *sem);
void sem_wait(struct semaphore *sem);

#endif