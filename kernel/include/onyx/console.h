/*
 * Copyright (c) 2024 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_CONSOLE_H
#define _ONYX_CONSOLE_H

#include <stddef.h>

#include <onyx/mm/slab.h>
#include <onyx/mutex.h>
#include <onyx/rcupdate.h>
#include <onyx/types.h>
#include <onyx/utils.h>

struct console_ops;

struct console
{
    const char *name;
    unsigned long refcount;
    unsigned long flags;
    const struct console_ops *ops;
    struct rcu_head rcu_head;
    struct mutex conlock;
    u32 last_seq_seen;
    void *priv;
};

#define CONSOLE_FLAG_CONTENDED (1 << 0)
#define CONSOLE_FLAG_VTERM     (1 << 1)

#define CONSOLE_WRITE_ATOMIC (1 << 0)
#define CONSOLE_WRITE_PANIC  (1 << 1)

struct console_ops
{
    int (*write)(const char *data, size_t size, unsigned int flags, struct console *con);
};

__BEGIN_CDECLS

static inline void console_init(struct console *con, const char *name,
                                const struct console_ops *ops)
{
    con->name = name;
    con->ops = ops;
    con->flags = 0;
    con->rcu_head.func = NULL;
    con->rcu_head.next = NULL;
    mutex_init(&con->conlock);
    con->last_seq_seen = 0;
    con->refcount = 1;
}

void con_register(struct console *con);
static inline void con_put(struct console *con)
{
    if (__atomic_sub_fetch(&con->refcount, 1, __ATOMIC_RELEASE) == 0)
        kfree_rcu(con, rcu_head);
}

static inline bool con_get_rcu(struct console *__rcu con)
{
    /* rcu_read_lock held */
    unsigned long ref = __atomic_load_n(&con->refcount, __ATOMIC_RELAXED);
    do
    {
        if (ref == 0)
            return false;
    } while (!__atomic_compare_exchange_n(&con->refcount, &ref, ref + 1, false, __ATOMIC_ACQUIRE,
                                          __ATOMIC_RELAXED));
    return true;
}

__END_CDECLS

#endif
