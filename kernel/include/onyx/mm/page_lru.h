/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_MM_PAGE_LRU_H
#define _ONYX_MM_PAGE_LRU_H

#include <onyx/list.h>
#include <onyx/spinlock.h>

struct page;

#define NR_LRU_LISTS 2

enum lru_state
{
    LRU_INACTIVE = 0,
    LRU_ACTIVE
};

struct page_lru
{
    /* LRU lists for the LRU-2Q + CLOCK algorithm */
    struct list_head lru_lists[NR_LRU_LISTS];
    struct spinlock lock;
};

CONSTEXPR static inline void page_lru_init(struct page_lru *lru)
{
    for (int i = 0; i < NR_LRU_LISTS; i++)
        INIT_LIST_HEAD(&lru->lru_lists[i]);
    spinlock_init(&lru->lock);
}

__BEGIN_CDECLS

void page_add_lru(struct page *page);
void page_remove_lru(struct page *page);

__END_CDECLS

#endif
