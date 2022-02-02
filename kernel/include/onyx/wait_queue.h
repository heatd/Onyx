/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
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

struct wait_queue_token
{
    struct thread *thread;
    void (*callback)(void *context, struct wait_queue_token *token);
    void *context;
    bool signaled;
    struct list_head token_node;

    constexpr wait_queue_token() : thread{}, callback{}, context{}, signaled{}, token_node{}
    {
    }
};

struct wait_queue
{
    struct spinlock lock;
    struct list_head token_list;

    constexpr wait_queue() : lock{}, token_list{}
    {
        INIT_LIST_HEAD(&token_list);
    }
};

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

#define WAIT_QUEUE_INIT(x) {.lock = {}, .token_list = LIST_HEAD_INIT(&x.token_list)};

static inline void init_wait_queue_head(struct wait_queue *q)
{
    INIT_LIST_HEAD(&q->token_list);
}

#endif
