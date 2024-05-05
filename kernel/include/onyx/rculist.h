/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_RCULIST_H
#define _ONYX_RCULIST_H

#include <onyx/list.h>
#include <onyx/rcupdate.h>

#define list_for_every_rcu(lh)                                                            \
    for (struct list_head *l = __atomic_load_n(&(lh)->next, __ATOMIC_RELAXED); l != (lh); \
         l = __atomic_load_n(&l->next, __ATOMIC_RELAXED))

static inline void __list_add_rcu(struct list_head *_new, struct list_head *prev,
                                  struct list_head *next)
{
    next->prev = _new;
    _new->next = next;
    _new->prev = prev;
    rcu_assign_pointer(prev->next, _new);
}

static inline void list_add_rcu(struct list_head *_new, struct list_head *head)
{
    __list_add(_new, head, head->next);
}

static inline void list_add_tail_rcu(struct list_head *_new, struct list_head *head)
{
    __list_add(_new, head->prev, head);
}

static inline void list_remove_rcu(struct list_head *node)
{
    list_remove_bulk(node->prev, node->next);
}

#endif
