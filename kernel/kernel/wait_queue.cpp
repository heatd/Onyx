/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#include <stddef.h>
#include <stdio.h>

#include <onyx/task_switching.h>
#include <onyx/wait_queue.h>

void wait_queue_wait(struct wait_queue *queue)
{
    struct thread *current = get_current_thread();
    struct wait_queue_token token;
    token.thread = current;
    token.callback = NULL;
    token.context = NULL, token.token_node.next = token.token_node.prev = NULL;
    token.signaled = false;

    sched_disable_preempt();

    set_current_state(THREAD_UNINTERRUPTIBLE);

    wait_queue_add(queue, &token);

    sched_enable_preempt();

    sched_yield();
}

struct wait_queue_token *wait_queue_wake_unlocked(struct wait_queue_token *token)
{
    if (!(token->flags & WQ_TOKEN_NO_DEQUEUE))
        list_remove(&token->token_node);
    token->signaled = true;
    return token;
}

void wait_queue_wake(struct wait_queue *queue)
{
    unsigned long cpu_flags = spin_lock_irqsave(&queue->lock);

    if (list_is_empty(&queue->token_list))
    {
        spin_unlock_irqrestore(&queue->lock, cpu_flags);
        return;
    }

    struct wait_queue_token *t = wait_queue_wake_unlocked(
        list_first_entry(&queue->token_list, struct wait_queue_token, token_node));

    if (t->callback)
        t->callback(t->context, t);

    thread_wake_up(t->thread);

    spin_unlock_irqrestore(&queue->lock, cpu_flags);
}

void wait_queue_wake_all(struct wait_queue *queue)
{
    struct wait_queue_token *waiter, *next;
    unsigned long cpu_flags = spin_lock_irqsave(&queue->lock);

    list_for_each_entry_safe (waiter, next, &queue->token_list, token_node)
    {
        struct wait_queue_token *t = wait_queue_wake_unlocked(waiter);

        if (t->callback)
            t->callback(t->context, t);
        thread_wake_up(t->thread);
    }

    spin_unlock_irqrestore(&queue->lock, cpu_flags);
}

/**
 * @brief Add a waiter to the wait queue, unlocked
 *
 * @param queue Queue to add a waiter to
 * @param token Waiter to add
 */
void __wait_queue_add(struct wait_queue *queue, struct wait_queue_token *token)
{
    if (token->flags & WQ_TOKEN_EXCLUSIVE)
        list_add_tail(&token->token_node, &queue->token_list);
    else
        list_add(&token->token_node, &queue->token_list);
}

void wait_queue_add(struct wait_queue *queue, struct wait_queue_token *token)
{
    unsigned long cpu_flags = spin_lock_irqsave(&queue->lock);

    __wait_queue_add(queue, token);

    spin_unlock_irqrestore(&queue->lock, cpu_flags);
}

/**
 * @brief Remove a waiter from the wait queue, unlocked
 *
 * @param queue Queue to remove a waiter from
 * @param token Waiter to remove
 */
void __wait_queue_remove(struct wait_queue *queue, struct wait_queue_token *token)
{
    struct list_head *node = &token->token_node;
    if (node->next != LIST_REMOVE_POISON)
        list_remove(node);

    list_assert_correct(&queue->token_list);

    token->callback = NULL;
    token->signaled = false;
    token->context = NULL;
}

void wait_queue_remove(struct wait_queue *queue, struct wait_queue_token *token)
{
    unsigned long cpu_flags = spin_lock_irqsave(&queue->lock);
    __wait_queue_remove(queue, token);
    spin_unlock_irqrestore(&queue->lock, cpu_flags);
}

bool wait_queue_may_delete(struct wait_queue *queue)
{
    unsigned long cpu_flags = spin_lock_irqsave(&queue->lock);

    bool may = list_is_empty(&queue->token_list);

    spin_unlock_irqrestore(&queue->lock, cpu_flags);

    return may;
}

/**
 * @brief Wake along a wait queue, internal version.
 * This version does not have locking.
 *
 * @param queue Queue to wake up
 * @param flags Flags for the wakeup
 * @param context Optional context flag for wake()
 * @param nr_exclusive Number of exclusive waiters to wake up.
 * @return Number of waiters woken up.
 */
unsigned long __wait_queue_wake(struct wait_queue *queue, unsigned int flags, void *context,
                                unsigned long nr_exclusive)
{
    unsigned long woken = 0;
    list_for_every_safe (&queue->token_list)
    {
        bool stop_afterwards = false;
        struct wait_queue_token *token = container_of(l, struct wait_queue_token, token_node);

        // The waiter may have some logic built in to check if we indeed must wake it.
        if (token->wake)
        {
            int st = token->wake(token, context);
            if (st == WQ_WAKE_DO_NOT_WAKE)
                continue;
            else if (st == WQ_WAKE_WAKE_EXCLUSIVE)
            {
                // token::wake wants us to wake up exclusively,
                // as if WQ_TOKEN_EXCLUSIVE were set.
                stop_afterwards = true;
            }
        }

        if (token->flags & WQ_TOKEN_EXCLUSIVE)
        {
            if (nr_exclusive == 0)
                break;
            nr_exclusive--;
        }

        // Dequeue the token from the wait queue
        list_remove(&token->token_node);
        token->signaled = true;
        if (token->callback)
            token->callback(context, token);

        thread_wake_up(token->thread);
        woken++;

        if (stop_afterwards) [[unlikely]]
            break;
    }

    return woken;
}
