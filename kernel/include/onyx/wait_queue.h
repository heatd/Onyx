/*
 * Copyright (c) 2019 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_WAIT_QUEUE_H
#define _ONYX_WAIT_QUEUE_H

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <onyx/list.h>
#include <onyx/scheduler.h>
#include <onyx/spinlock.h>
#include <onyx/task_switching.h>

#define WQ_TOKEN_EXCLUSIVE (1u << 0)

/* Return values for wait_queue_token::wake */
#define WQ_WAKE_DO_NOT_WAKE    -1
#define WQ_WAKE_WAKE_EXCLUSIVE 0
#define WQ_WAKE_DO_WAKE        1

struct wait_queue_token
{
    struct thread *thread;
    void (*callback)(void *context, struct wait_queue_token *token);
    int (*wake)(struct wait_queue_token *token, void *context);
    void *context;
    struct list_head token_node;
    unsigned short flags;
    bool signaled;
};

// clang-format off
#ifdef __cplusplus
constexpr
#endif
static inline void init_wq_token(struct wait_queue_token *token)
{
    token->thread = NULL;
    token->callback = NULL;
    token->wake = NULL;
    token->context = NULL;
    token->signaled = false;
}

// clang-format on

struct wait_queue
{
    struct spinlock lock;
    struct list_head token_list;

#ifdef __cplusplus
    constexpr wait_queue() : lock{}, token_list{}
    {
        INIT_LIST_HEAD(&token_list);
    }
#endif
};

#define WQ_WAKE_ONE (1u << 0)

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
                                unsigned long nr_exclusive);

/**
 * @brief Add a waiter to the wait queue, unlocked
 *
 * @param queue Queue to add a waiter to
 * @param token Waiter to add
 */
void __wait_queue_add(struct wait_queue *queue, struct wait_queue_token *token);

/**
 * @brief Remove a waiter from the wait queue, unlocked
 *
 * @param queue Queue to remove a waiter from
 * @param token Waiter to remove
 */
void __wait_queue_remove(struct wait_queue *queue, struct wait_queue_token *token);

/**
 * @brief Check if the wait queue is empty, unlocked.
 *
 * @param queue Queue to check
 * @return True if empty, else false.
 */
static inline bool __wait_queue_is_empty(const struct wait_queue *queue)
{
    return list_is_empty(&queue->token_list);
}

void wait_queue_wait(struct wait_queue *queue);
void wait_queue_wake(struct wait_queue *queue);
void wait_queue_wake_all(struct wait_queue *queue);
void wait_queue_add(struct wait_queue *queue, struct wait_queue_token *token);
void wait_queue_remove(struct wait_queue *queue, struct wait_queue_token *token);
bool wait_queue_may_delete(struct wait_queue *queue);

bool signal_is_pending();

#define __wait_for_event(wq, cond, state, cmd)                        \
    ({                                                                \
        long __ret = 0;                                               \
        struct wait_queue_token token;                                \
        if (cond)                                                     \
            goto out_final;                                           \
        init_wq_token(&token);                                        \
                                                                      \
        set_current_state(state);                                     \
        while (true)                                                  \
        {                                                             \
            token.thread = get_current_thread();                      \
            wait_queue_add(wq, &token);                               \
            if (cond)                                                 \
                break;                                                \
            if (state == THREAD_INTERRUPTIBLE && signal_is_pending()) \
            {                                                         \
                __ret = -EINTR;                                       \
                goto __out;                                           \
            }                                                         \
            cmd;                                                      \
            wait_queue_remove(wq, &token);                            \
        }                                                             \
    __out:                                                            \
        wait_queue_remove(wq, &token);                                \
        set_current_state(THREAD_RUNNABLE);                           \
    out_final:;                                                       \
        __ret;                                                        \
    })

#define __wait_for_event_with_timeout(wq, cond, state, timeout_ns, cmd) \
    ({                                                                  \
        hrtime_t ____timeout = timeout_ns;                              \
        long __ret = 0;                                                 \
        struct wait_queue_token token;                                  \
        if (cond)                                                       \
            goto out_final;                                             \
        init_wq_token(&token);                                          \
                                                                        \
        set_current_state(state);                                       \
        while (true)                                                    \
        {                                                               \
            token.thread = get_current_thread();                        \
            wait_queue_add(wq, &token);                                 \
            if (cond)                                                   \
                goto __out;                                             \
            if (state == THREAD_INTERRUPTIBLE && signal_is_pending())   \
            {                                                           \
                __ret = -EINTR;                                         \
                goto __out;                                             \
            }                                                           \
            cmd;                                                        \
            wait_queue_remove(wq, &token);                              \
        }                                                               \
    __out:                                                              \
        wait_queue_remove(wq, &token);                                  \
        set_current_state(THREAD_RUNNABLE);                             \
    out_final:                                                          \
        __ret;                                                          \
    })

#define wait_for_event_timeout(wq, cond, _timeout)                                          \
    __wait_for_event_with_timeout(                                                          \
        wq, cond, THREAD_UNINTERRUPTIBLE, _timeout, ____timeout = sched_sleep(____timeout); \
        if (____timeout == 0) {                                                             \
            __ret = -ETIMEDOUT;                                                             \
            goto __out;                                                                     \
        })

#define wait_for_event_timeout_interruptible(wq, cond, _timeout)                          \
    __wait_for_event_with_timeout(                                                        \
        wq, cond, THREAD_INTERRUPTIBLE, _timeout, ____timeout = sched_sleep(____timeout); \
        if (____timeout == 0) {                                                           \
            __ret = -ETIMEDOUT;                                                           \
            goto __out;                                                                   \
        })

#define wait_for_event_locked_timeout_interruptible(wq, cond, _timeout, lock)            \
    __wait_for_event_with_timeout(                                                       \
        wq, cond, THREAD_INTERRUPTIBLE, _timeout, spin_unlock(lock);                     \
        ____timeout = sched_sleep(____timeout); spin_lock(lock); if (____timeout == 0) { \
            __ret = -ETIMEDOUT;                                                          \
            goto __out;                                                                  \
        })

#define wait_for_event(wq, cond) __wait_for_event(wq, cond, THREAD_UNINTERRUPTIBLE, sched_yield())

#define wait_for_event_interruptible(wq, cond) \
    __wait_for_event(wq, cond, THREAD_INTERRUPTIBLE, sched_yield())

#define wait_for_event_locked(wq, cond, lock)                                            \
    __wait_for_event(wq, cond, THREAD_UNINTERRUPTIBLE, spin_unlock(lock); sched_yield(); \
                     spin_lock(lock))

#define wait_for_event_locked_interruptible(wq, cond, lock)                            \
    __wait_for_event(wq, cond, THREAD_INTERRUPTIBLE, spin_unlock(lock); sched_yield(); \
                     spin_lock(lock))

#define wait_for_event_mutex_interruptible(wq, cond, lock)                              \
    __wait_for_event(wq, cond, THREAD_INTERRUPTIBLE, mutex_unlock(lock); sched_yield(); \
                     mutex_lock(lock))

#define wait_for_event_socklocked_interruptible(wq, cond)                                          \
    __wait_for_event(wq, cond, THREAD_INTERRUPTIBLE, socket_lock.unlock_sock(this); sched_yield(); \
                     socket_lock.lock())

#define wait_for_event_socklocked_interruptible_2(wq, cond, sock)                           \
    __wait_for_event(wq, cond, THREAD_INTERRUPTIBLE, (sock)->socket_lock.unlock_sock(sock); \
                     sched_yield(); (sock)->socket_lock.lock())

#define WAIT_QUEUE_INIT(x) {.lock = {}, .token_list = LIST_HEAD_INIT(&x.token_list)};

static inline void init_wait_queue_head(struct wait_queue *q)
{
    INIT_LIST_HEAD(&q->token_list);
}

#endif
