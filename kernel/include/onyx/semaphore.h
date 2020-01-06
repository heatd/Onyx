/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_SEM_H
#define _ONYX_SEM_H

#ifndef __cplusplus
#include <stdatomic.h>
#endif

#include <onyx/scheduler.h>
#include <onyx/spinlock.h>

struct semaphore
{
	thread_t *head;
	thread_t *tail;
	struct spinlock lock;
#ifndef __cplusplus
	atomic_long counter;
#else
	long counter;
#endif
};


#ifdef __cplusplus
extern "C" {
#endif

void sem_init(struct semaphore *sem, long counter);
void sem_signal(struct semaphore *sem);
void sem_wait(struct semaphore *sem);

#ifdef __cplusplus
}
#endif

#endif