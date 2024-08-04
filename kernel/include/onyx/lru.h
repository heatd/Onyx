/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_LRU_H
#define _ONYX_LRU_H

#include <onyx/list.h>
#include <onyx/spinlock.h>

/**
 * @brief Simple LRU list implementation
 *
 */
struct lru_list
{
    struct list_head obj_list;
    struct spinlock lock;
};

__BEGIN_CDECLS

static inline void lru_list_init(struct lru_list *lru)
{
    INIT_LIST_HEAD(&lru->obj_list);
    spinlock_init(&lru->lock);
}

void lru_list_add(struct lru_list *lru, struct list_head *object);
void lru_list_remove(struct lru_list *lru, struct list_head *object);

enum lru_walk_ret
{
    LRU_WALK_ROTATE = 0,
    LRU_WALK_SKIP,
    LRU_WALK_STOP,
    LRU_WALK_REMOVED,
};

void lru_list_walk(struct lru_list *lru,
                   enum lru_walk_ret (*walk)(struct lru_list *lru, struct list_head *obj,
                                             void *data),
                   void *data);

__END_CDECLS

#endif
