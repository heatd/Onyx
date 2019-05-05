/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_WAIT_QUEUE_H
#define _ONYX_WAIT_QUEUE_H

#include <onyx/scheduler.h>
#include <onyx/mutex.h>

struct wait_queue_token
{
	struct thread *thread;
	struct wait_queue_token *next;
};

struct wait_queue
{
	struct mutex lock;
	struct wait_queue_token *list;
};

void wait_queue_wait(struct wait_queue *queue);
void wait_queue_wake(struct wait_queue *queue);
void wait_queue_wake_all(struct wait_queue *queue);

#endif