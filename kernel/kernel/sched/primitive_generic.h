/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_SCHEDULER_PRIMITIVE_GENERIC_H
#define _ONYX_SCHEDULER_PRIMITIVE_GENERIC_H

#define enqueue_thread_generic(primitive_name, primitive_struct)                       \
    static void enqueue_thread_##primitive_name(primitive_struct *s, thread_t *thread) \
    {                                                                                  \
                                                                                       \
        if (!s->head)                                                                  \
        {                                                                              \
            s->head = s->tail = thread;                                                \
            thread->sem_prev = thread->sem_next = NULL;                                \
        }                                                                              \
        else                                                                           \
        {                                                                              \
            s->tail->sem_next = thread;                                                \
            thread->sem_prev = s->tail;                                                \
            s->tail = thread;                                                          \
            thread->sem_next = NULL;                                                   \
        }                                                                              \
    }

#define dequeue_thread_generic(primitive_name, primitive_struct)                       \
    static void dequeue_thread_##primitive_name(primitive_struct *s, thread_t *thread) \
    {                                                                                  \
        if (s->head == thread)                                                         \
        {                                                                              \
            s->head = thread->sem_next;                                                \
            if (thread->sem_next)                                                      \
            {                                                                          \
                thread->sem_next->sem_prev = NULL;                                     \
            }                                                                          \
        }                                                                              \
        else                                                                           \
        {                                                                              \
            if (thread->sem_prev)                                                      \
                thread->sem_prev->sem_next = thread->sem_next;                         \
            if (thread->sem_next)                                                      \
            {                                                                          \
                thread->sem_next->sem_prev = thread->sem_prev;                         \
            }                                                                          \
            else                                                                       \
            {                                                                          \
                s->tail = thread->sem_prev;                                            \
            }                                                                          \
        }                                                                              \
                                                                                       \
        if (s->tail == thread)                                                         \
        {                                                                              \
            s->tail = thread->sem_prev;                                                \
        }                                                                              \
                                                                                       \
        thread->sem_next = thread->sem_prev = NULL;                                    \
    }

#define prepare_sleep_generic(typenm, type)                       \
    void prepare_sleep_##typenm(type *p, int state)               \
    {                                                             \
        thread *t = get_current_thread();                         \
        sched_disable_preempt();                                  \
                                                                  \
        set_current_state(state);                                 \
        unsigned long __cpu_flags = spin_lock_irqsave(&p->llock); \
        enqueue_thread_##typenm(p, t);                            \
        spin_unlock_irqrestore(&p->llock, __cpu_flags);           \
    }

#endif
