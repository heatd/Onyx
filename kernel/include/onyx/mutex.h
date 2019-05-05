/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_MUTEX_H
#define _KERNEL_MUTEX_H

#include <onyx/scheduler.h>

struct mutex
{
	struct spinlock llock;
	thread_t *head;
	thread_t *tail;
	unsigned long counter;
	struct thread *owner;
};

#define MUTEX_INITIALIZER {0}

#ifdef __cplusplus
extern "C" {
#endif

void mutex_lock(struct mutex *m);
void mutex_unlock(struct mutex *m);

#ifdef __cplusplus
}
#endif

#endif
