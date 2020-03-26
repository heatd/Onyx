/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_WAIT_QUEUE_H
#define _ONYX_WAIT_QUEUE_H

#include <stdbool.h>
#include <string.h>

#include <onyx/scheduler.h>
#include <onyx/spinlock.h>
#include <onyx/list.h>
struct wait_queue_token
{
	struct thread *thread;
	void (*callback)(void *context, struct wait_queue_token *token);
	void *context;
	bool signaled;
	struct list_head token_node;
};

struct wait_queue
{
	struct spinlock lock;
	struct list_head token_list;
};

#ifdef __cplusplus
extern "C" {
#endif

void wait_queue_wait(struct wait_queue *queue);
void wait_queue_wake(struct wait_queue *queue);
void wait_queue_wake_all(struct wait_queue *queue);
void wait_queue_add(struct wait_queue *queue, struct wait_queue_token *token);
void wait_queue_remove(struct wait_queue *queue, struct wait_queue_token *token);
bool wait_queue_may_delete(struct wait_queue *queue);

#define __wait_for_event(wq, cond, state, cmd)	\
do											\
{											\
											\
	if(cond)								\
		break;								\
											\
	struct wait_queue_token token;			\
											\
	set_current_state(state);				\
	while(true)								\
	{										\
		memset(&token, 0, sizeof(token));		\
		token.thread = get_current_thread();	\
		wait_queue_add(wq, &token);			\
		if(cond)							\
			break;							\
		cmd;								\
	}										\
											\
	wait_queue_remove(wq, &token);			\
	set_current_state(THREAD_RUNNABLE);		\
} while(0);

#define wait_for_event(wq, cond)	__wait_for_event(wq, cond, THREAD_UNINTERRUPTIBLE, sched_yield())

#define wait_for_event_locked(wq, cond, lock) __wait_for_event(wq, cond, THREAD_UNINTERRUPTIBLE, \
	spin_unlock(lock);sched_yield();spin_lock(lock))

#define WAIT_QUEUE_INIT(x)			{.lock = {}, .token_list = LIST_HEAD_INIT(&x.token_list) };

static inline void init_wait_queue_head(struct wait_queue *q)
{
	memset(&q->lock, 0, sizeof(q->lock));
	INIT_LIST_HEAD(&q->token_list);
}

#ifdef __cplusplus
}
#endif

#endif