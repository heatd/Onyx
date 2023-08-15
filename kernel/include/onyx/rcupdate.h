/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the LGPL-2.0-only license.
 *
 * SPDX-License-Identifier: LGPL-2.0-only
 */
#ifndef _ONYX_RCUPDATE_H
#define _ONYX_RCUPDATE_H

#include <onyx/preempt.h>

#define rcu_read_lock()   sched_disable_preempt()
#define rcu_read_unlock() sched_enable_preempt()

struct rcu_head
{
    struct rcu_head *next;
    void (*func)(struct rcu_head *head);
};

void call_rcu(struct rcu_head *head, void (*callback)(struct rcu_head *head));
void synchronize_rcu();

/**
 * @brief Handle a quiescent state
 * Raises the softirq if required.
 *
 */
void rcu_do_quiesc();

/**
 * @brief Do RCU work (softirq routine)
 *
 */
void rcu_work();

#define rcu_dereference(ptr) __atomic_load_n(&(ptr), __ATOMIC_RELAXED)

#define rcu_assign_pointer(ptr, val)             \
    ({                                           \
        __atomic_thread_fence(__ATOMIC_RELEASE); \
        (ptr) = (val);                           \
    })

#define __rcu

#endif
