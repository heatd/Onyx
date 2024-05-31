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

struct page_lru
{
    /* Very simple single LRU list (for the CLOCK algorithm) */
    struct list_head lru_list;
    struct spinlock lock;
};

CONSTEXPR static inline void page_lru_init(struct page_lru *lru)
{
    INIT_LIST_HEAD(&lru->lru_list);
    spinlock_init(&lru->lock);
}

__BEGIN_CDECLS

void page_add_lru(struct page *page);
void page_remove_lru(struct page *page);

__END_CDECLS

#endif
