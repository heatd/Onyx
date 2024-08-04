/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/lru.h>

void lru_list_add(struct lru_list *lru, struct list_head *object)
{
    spin_lock(&lru->lock);
    list_add_tail(object, &lru->obj_list);
    spin_unlock(&lru->lock);
}

void lru_list_remove(struct lru_list *lru, struct list_head *object)
{
    spin_lock(&lru->lock);
    list_remove(object);
    spin_unlock(&lru->lock);
}

void lru_list_walk(struct lru_list *lru,
                   enum lru_walk_ret (*walk)(struct lru_list *lru, struct list_head *obj,
                                             void *data),
                   void *data)
{
    spin_lock(&lru->lock);
    list_for_every_safe (&lru->obj_list)
    {
        enum lru_walk_ret ret = walk(lru, l, data);
        switch (ret)
        {
            case LRU_WALK_ROTATE:
                list_remove(l);
                list_add_tail(l, &lru->obj_list);
                break;
            case LRU_WALK_SKIP:
            case LRU_WALK_REMOVED:
                continue;
            case LRU_WALK_STOP:
                goto out;
        }
    }

out:
    spin_unlock(&lru->lock);
}
