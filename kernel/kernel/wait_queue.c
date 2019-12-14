/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stddef.h>
#include <onyx/wait_queue.h>
#include <onyx/task_switching.h>

static void append_to_queue(struct wait_queue *queue, struct wait_queue_token *token)
{
	struct wait_queue_token *p = queue->token_tail;

	if(!queue->token_head)
		queue->token_head = token;


	if(p)
	{
		p->next = token;
		token->prev = p;
	}

	queue->token_tail = token;
}

static void dequeue_token(struct wait_queue *q, struct wait_queue_token *token)
{
	if(q->token_head == token)
	{
		q->token_head = token->next;
	}

	if(q->token_tail == token)
	{
		q->token_tail = token->prev;
	}

	if(token->prev)	token->prev->next = token->next;
	if(token->next)	token->next->prev = token->prev;

	token->prev = token->next = NULL;
}

void wait_queue_wait(struct wait_queue *queue)
{
	struct thread *current = get_current_thread();
	struct wait_queue_token token;
	token.thread = current;
	token.callback = NULL;
	token.context = NULL,
	token.next = token.prev = NULL;
	token.signaled = false;

	sched_disable_preempt();

	set_current_state(THREAD_UNINTERRUPTIBLE);

	wait_queue_add(queue, &token);

	sched_enable_preempt();

	sched_yield();
}

struct wait_queue_token *wait_queue_wake_unlocked(struct wait_queue *queue)
{
	struct wait_queue_token *token = queue->token_head;

	dequeue_token(queue, token);

	return token;
}

void wait_queue_wake(struct wait_queue *queue)
{
	spin_lock(&queue->lock);

	struct wait_queue_token *t = wait_queue_wake_unlocked(queue);

	spin_unlock(&queue->lock);

	if(t->callback) t->callback(t->context, t);

	thread_wake_up(t->thread);
}

void wait_queue_wake_all(struct wait_queue *queue)
{
	spin_lock(&queue->lock);

	while(queue->token_head)
	{
		struct wait_queue_token *t = wait_queue_wake_unlocked(queue);

		if(t->callback) t->callback(t->context, t);
		thread_wake_up(t->thread);
	}

	spin_unlock(&queue->lock);
	
}

void wait_queue_add(struct wait_queue *queue, struct wait_queue_token *token)
{
	spin_lock(&queue->lock);

	token->prev = token->next = NULL;
	append_to_queue(queue, token);

	spin_unlock(&queue->lock);
}

void wait_queue_remove(struct wait_queue *queue, struct wait_queue_token *token)
{
	spin_lock(&queue->lock);

	dequeue_token(queue, token);

	spin_unlock(&queue->lock);
}