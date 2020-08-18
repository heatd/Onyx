/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stddef.h>
#include <stdio.h>
#include <onyx/wait_queue.h>
#include <onyx/task_switching.h>


void wait_queue_wait(struct wait_queue *queue)
{
	struct thread *current = get_current_thread();
	struct wait_queue_token token;
	token.thread = current;
	token.callback = NULL;
	token.context = NULL,
	token.token_node.next = token.token_node.prev = NULL;
	token.signaled = false;

	sched_disable_preempt();

	set_current_state(THREAD_UNINTERRUPTIBLE);

	wait_queue_add(queue, &token);

	sched_enable_preempt();

	sched_yield();
}

struct wait_queue_token *wait_queue_wake_unlocked(struct wait_queue *queue)
{
	MUST_HOLD_LOCK(&queue->lock);
	assert(list_is_empty(&queue->token_list) == false);

	struct list_head *token_lh = list_first_element(&queue->token_list);

	assert(token_lh != NULL);

	struct wait_queue_token *token = container_of(token_lh, struct wait_queue_token, token_node);

	list_remove(token_lh);

	list_assert_correct(&queue->token_list);

	token->signaled = true;

	return token;
}

void wait_queue_wake(struct wait_queue *queue)
{
	unsigned long cpu_flags = spin_lock_irqsave(&queue->lock);

	if(list_is_empty(&queue->token_list))
	{
		spin_unlock_irqrestore(&queue->lock, cpu_flags);
		return;
	}
	
	struct wait_queue_token *t = wait_queue_wake_unlocked(queue);

	if(t->callback) t->callback(t->context, t);

	thread_wake_up(t->thread);

	spin_unlock_irqrestore(&queue->lock, cpu_flags);
}

void wait_queue_wake_all(struct wait_queue *queue)
{
	unsigned long cpu_flags = spin_lock_irqsave(&queue->lock);

	while(!list_is_empty(&queue->token_list))
	{
		struct wait_queue_token *t = wait_queue_wake_unlocked(queue);

		if(t->callback) t->callback(t->context, t);
		thread_wake_up(t->thread);
	}

	spin_unlock_irqrestore(&queue->lock, cpu_flags);
}

void wait_queue_add(struct wait_queue *queue, struct wait_queue_token *token)
{
	unsigned long cpu_flags = spin_lock_irqsave(&queue->lock);

	assert(token->token_node.prev == NULL);

	list_add_tail(&token->token_node, &queue->token_list);

	list_assert_correct(&queue->token_list);

	spin_unlock_irqrestore(&queue->lock, cpu_flags);
}

void wait_queue_remove(struct wait_queue *queue, struct wait_queue_token *token)
{
	unsigned long cpu_flags = spin_lock_irqsave(&queue->lock);
	
	struct list_head *node = &token->token_node;
	if(node->next != LIST_REMOVE_POISON)
		list_remove(node);

	list_assert_correct(&queue->token_list);

	token->callback = NULL;
	token->signaled = false;
	token->context = NULL;

	spin_unlock_irqrestore(&queue->lock, cpu_flags);	
}

bool wait_queue_may_delete(struct wait_queue *queue)
{
	unsigned long cpu_flags = spin_lock_irqsave(&queue->lock);

	bool may = list_is_empty(&queue->token_list);

	spin_unlock_irqrestore(&queue->lock, cpu_flags);

	return may;
}
