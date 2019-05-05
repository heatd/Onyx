/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stddef.h>
#include <onyx/wait_queue.h>

void append_to_queue(struct wait_queue *queue, struct wait_queue_token *token)
{
	struct wait_queue_token **pp = &queue->list;

	while(*pp)
		pp = &(*pp)->next;
	
	*pp = token;
}

void wait_queue_wait(struct wait_queue *queue)
{
	struct thread *current = get_current_thread();
	struct wait_queue_token token;
	token.thread = current;
	token.next = NULL;

	mutex_lock(&queue->lock);

	append_to_queue(queue, &token);

	sched_disable_preempt();

	mutex_unlock(&queue->lock);

	sched_lock(current);

	sched_enable_preempt();

	__sched_block(current);
}

void wait_queue_wake(struct wait_queue *queue)
{
	mutex_lock(&queue->lock);

	assert(queue->list != NULL);

	struct wait_queue_token *token = queue->list;

	queue->list = queue->list->next;

	mutex_unlock(&queue->lock);

	thread_wake_up(token->thread);
}

void wait_queue_wake_all(struct wait_queue *queue)
{
	while(queue->list)
		wait_queue_wake(queue);
}