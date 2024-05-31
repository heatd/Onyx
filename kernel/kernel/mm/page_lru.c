/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/mm/page_lru.h>
#include <onyx/page.h>

void page_add_lru(struct page *page)
{
    DCHECK(!page_flag_set(page, PAGE_FLAG_LRU));
    DCHECK(page->owner != NULL);
    struct page_lru *lru = page_to_page_lru(page);
    spin_lock(&lru->lock);
    list_add_tail(&page->lru_node, &lru->lru_list);
    page_test_set_flag(page, PAGE_FLAG_LRU);
    spin_unlock(&lru->lock);
}

void page_remove_lru(struct page *page)
{
    DCHECK(page_flag_set(page, PAGE_FLAG_LRU));
    struct page_lru *lru = page_to_page_lru(page);
    spin_lock(&lru->lock);
    list_remove(&page->lru_node);
    __atomic_and_fetch(&page->flags, ~PAGE_FLAG_LRU, __ATOMIC_RELEASE);
    spin_unlock(&lru->lock);
}
