/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_CONDVAR_H
#define _ONYX_CONDVAR_H

#include <onyx/mutex.h>
#include <onyx/scheduler.h>

struct cond
{
	struct spinlock llock;
	thread_t *head;
	thread_t *tail;
};

void condvar_wait(struct cond *c, struct mutex *mutex);
void condvar_signal(struct cond *c);
void condvar_broadcast(struct cond *c);

#endif