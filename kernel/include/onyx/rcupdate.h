/*
 * Copyright (c) 2023 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 license.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_RCUPDATE_H
#define _ONYX_RCUPDATE_H

#include <stddef.h>

#include <onyx/atomic.h>
#include <onyx/preempt.h>

#define rcu_read_lock()   sched_disable_preempt()
#define rcu_read_unlock() sched_enable_preempt()

__BEGIN_CDECLS

struct rcu_head
{
    struct rcu_head *next;
    void (*func)(struct rcu_head *head);
};

void call_rcu(struct rcu_head *head, void (*callback)(struct rcu_head *head));
void synchronize_rcu();
void __kfree_rcu(struct rcu_head *head, unsigned long off);

#ifdef __cplusplus
#define _Static_assert(x, m) static_assert(x, m)
#endif

#define is_kfree_rcu_off(off) ((off) < 4096)
#define kfree_rcu(ptr, head)                                                                   \
    ({                                                                                         \
        unsigned long off = offsetof(__typeof__(*(ptr)), head);                                \
        _Static_assert(                                                                        \
            is_kfree_rcu_off(offsetof(__typeof__(*(ptr)), head)),                              \
            "kfree_rcu's rcu_head needs to be within 4096 bytes off the start of the struct"); \
        __kfree_rcu(&(ptr)->head, off);                                                        \
    })

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

__END_CDECLS

#define rcu_assign_pointer(ptr, val) \
    ({                               \
        smp_wmb();                   \
        (ptr) = (val);               \
    })

#ifdef __cplusplus

#include <onyx/utility.hpp>

class auto_rcu_lock
{
public:
    auto_rcu_lock()
    {
        rcu_read_lock();
    }

    ~auto_rcu_lock()
    {
        rcu_read_unlock();
    }

    CLASS_DISALLOW_COPY(auto_rcu_lock);
    CLASS_DISALLOW_MOVE(auto_rcu_lock);
};
#endif

#ifdef __CHECKER__
#define __rcu               __attribute__((noderef, address_space(100)))
#define __force             __attribute__((force))
#define __rcu_forcecast(p)  ((__typeof__(*(p)) *__force) p)
/* Check for __rcu in sparse by casting the pointer to an __rcu one, and then comparing. Comparing
 * will trigger an address-space mismatch warning if p is not __rcu */
#define rcu_check_sparse(p) ((void) (((__typeof__(*(p)) __rcu *__force) p) == p))
#else
#define __rcu
#define __rcu_forcecast(p) (p)
#define rcu_check_sparse(ptr)
#endif

#define rcu_dereference(ptr)                                        \
    ({                                                              \
        rcu_check_sparse(ptr);                                      \
        __rcu_forcecast(__atomic_load_n(&(ptr), __ATOMIC_RELAXED)); \
    })

#define rcu_dereference_protected(p, c) \
    ({                                  \
        rcu_check_sparse(p);            \
        __rcu_forcecast(p);             \
    })

#define rcu_dereference_check(ptr, c) rcu_dereference(ptr)

#endif
