/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_RCULIST_H
#define _ONYX_RCULIST_H

#include <onyx/atomic.h>
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

#define list_entry_rcu(ptr, type, member) container_of(READ_ONCE(ptr), type, member)
/**
 * list_for_each_entry_rcu	-	iterate over rcu list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 * @cond:	optional lockdep expression if called from non-RCU protection.
 *
 * This list-traversal primitive may safely run concurrently with
 * the _rcu list-mutation primitives such as list_add_rcu()
 * as long as the traversal is guarded by rcu_read_lock().
 */
#define list_for_each_entry_rcu(pos, head, member, cond...)                                    \
    for (pos = list_entry_rcu((head)->next, __typeof__(*pos), member); &pos->member != (head); \
         pos = list_entry_rcu(pos->member.next, __typeof__(*pos), member))

#endif
