/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_MUTEX_H
#define _KERNEL_MUTEX_H

#include <string.h>

#include <onyx/scheduler.h>
#include <onyx/list.h>

struct mutex
{
	struct spinlock llock;
	struct list_head thread_list;
	unsigned long counter;
	struct thread *owner;
};

#define DECLARE_MUTEX(name)	struct mutex name = {.thread_list = LIST_HEAD_INIT(name.thread_list)};

#define MUTEX_INITIALIZER {.thread_list = LIST_HEAD_INIT(thread_list)}

static inline void mutex_init(struct mutex *mutex)
{
	memset(mutex, 0, sizeof(*mutex));
	INIT_LIST_HEAD(&mutex->thread_list);
}

#ifdef __cplusplus
extern "C" {
#endif

void mutex_lock(struct mutex *m);
void mutex_unlock(struct mutex *m);
int mutex_lock_interruptible(struct mutex *mutex);

#define MUST_HOLD_MUTEX(m)		assert((m)->counter == 1 && (m)->owner == get_current_thread())

#ifdef __cplusplus
}
#endif

#endif
