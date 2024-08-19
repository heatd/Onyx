/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/mm/page_lru.h>
#include <onyx/page.h>

static inline int page_to_state(struct page *page)
{
    return page_flag_set(page, PAGE_FLAG_ANON) ? LRU_ANON_OFF : 0;
}

void page_add_lru(struct page *page)
{
    DCHECK(!page_flag_set(page, PAGE_FLAG_LRU));
    struct page_lru *lru = page_to_page_lru(page);
    inc_page_stat(page, NR_INACTIVE_FILE + page_to_state(page));
    spin_lock(&lru->lock);
    list_add_tail(&page->lru_node, &lru->lru_lists[LRU_INACTIVE_BASE + page_to_state(page)]);
    page_test_set_flag(page, PAGE_FLAG_LRU);
    spin_unlock(&lru->lock);
}

void page_remove_lru(struct page *page)
{
    DCHECK(page_flag_set(page, PAGE_FLAG_LRU));
    struct page_lru *lru = page_to_page_lru(page);
    spin_lock(&lru->lock);
    list_remove(&page->lru_node);
    if (page_flag_set(page, PAGE_FLAG_ACTIVE))
        dec_page_stat(page, NR_ACTIVE_FILE + page_to_state(page));
    else
        dec_page_stat(page, NR_INACTIVE_FILE + page_to_state(page));
    __atomic_and_fetch(&page->flags, ~PAGE_FLAG_LRU, __ATOMIC_RELEASE);
    spin_unlock(&lru->lock);
}

static void page_activate(struct page *page)
{
    struct page_lru *lru = page_to_page_lru(page);
    spin_lock(&lru->lock);

    /* Setting ACTIVE is protected by the page_lru lock, so we shouldn't race here... */
    if (!page_flag_set(page, PAGE_FLAG_ACTIVE))
    {
        list_remove(&page->lru_node);
        page_set_flag(page, PAGE_FLAG_ACTIVE);
        dec_page_stat(page, NR_INACTIVE_FILE + page_to_state(page));
        inc_page_stat(page, NR_ACTIVE_FILE + page_to_state(page));
        __atomic_and_fetch(&page->flags, ~PAGE_FLAG_REFERENCED, __ATOMIC_RELEASE);
        list_add_tail(&page->lru_node, &lru->lru_lists[LRU_ACTIVE_BASE + +page_to_state(page)]);
    }

    spin_unlock(&lru->lock);
}

void page_promote_referenced(struct page *page)
{
    /* Promote a page in the page LRUs. We go from (considering Active, Referenced) (0,0) -> (0, 1)
     * -> (1, 0) -> (1, 1). In reality we could interpret this as a generation counter. Some slight
     * imprecision is tolerated, so we can skip all sorts of awful locking or cmpxchg stuff we would
     * need to pull off. */
    if (!page_flag_set(page, PAGE_FLAG_REFERENCED))
    {
        /* go from unref'd, inactive to ref'd, inactive */
        page_set_flag(page, PAGE_FLAG_REFERENCED);
    }
    else if (page_flag_set(page, PAGE_FLAG_LRU))
    {
        /* Referenced, activate. Note that we only try to activate if the page is in the LRU system
         * yet. If not, ignore. Trying to activate a page that's not quite in LRU yet will lead to
         * races. */
        page_activate(page);
    }
}

void page_lru_demote_reclaim(struct page *page)
{
    struct page_lru *lru = page_to_page_lru(page);

    if (page_flag_set(page, PAGE_FLAG_DIRTY) || page_locked(page))
        return;

    if (!page_test_clear_lru(page))
        return;

    spin_lock(&lru->lock);

    /* We _know_ we were in the lru. So remove ourselves and add ourselves to the head. Our page
     * reference makes sure the page wasn't reused. */
    list_remove(&page->lru_node);
    list_add(&page->lru_node, &lru->lru_lists[LRU_INACTIVE_BASE + page_to_state(page)]);
    page_set_lru(page);

    if (page_test_active(page))
    {
        dec_page_stat(page, NR_ACTIVE_FILE + page_to_state(page));
        inc_page_stat(page, NR_INACTIVE_FILE + page_to_state(page));
    }

    page_clear_active(page);
    spin_unlock(&lru->lock);
}
