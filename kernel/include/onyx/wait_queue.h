/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_WAIT_QUEUE_H
#define _ONYX_WAIT_QUEUE_H

#include <onyx/scheduler.h>
#include <onyx/spinlock.h>

struct wait_queue_token
{
	struct thread *thread;
	void (*callback)(void *context, struct wait_queue_token *token);
	void *context;
	bool signaled;
	struct wait_queue_token *prev, *next;
};

struct wait_queue
{
	struct spinlock lock;
	struct wait_queue_token *token_head, *token_tail;
};

#ifdef __cplusplus
extern "C" {
#endif

void wait_queue_wait(struct wait_queue *queue);
void wait_queue_wake(struct wait_queue *queue);
void wait_queue_wake_all(struct wait_queue *queue);
void wait_queue_add(struct wait_queue *queue, struct wait_queue_token *token);
void wait_queue_remove(struct wait_queue *queue, struct wait_queue_token *token);

#ifdef __cplusplus
}
#endif

#endif