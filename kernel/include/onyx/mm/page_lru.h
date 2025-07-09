/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_MM_PAGE_LRU_H
#define _ONYX_MM_PAGE_LRU_H

#include <onyx/list.h>
#include <onyx/spinlock.h>

struct page;
struct folio;

#define LRU_ANON_OFF 2
enum lru_state
{
    LRU_INACTIVE_BASE = 0,
    LRU_INACTIVE_FILE = 0,
    LRU_ACTIVE_BASE,
    LRU_ACTIVE_FILE = LRU_ACTIVE_BASE,
    LRU_INACTIVE_ANON,
    LRU_ACTIVE_ANON,
    NR_LRU_LISTS
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

void folio_add_lru(struct folio *folio);
void folio_remove_lru(struct folio *folio);
void page_lru_demote_reclaim(struct folio *folio);

__END_CDECLS

#endif
