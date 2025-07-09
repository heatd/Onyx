/*
 * Copyright (c) 2024 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/local_lock.h>
#include <onyx/mm/page_lru.h>
#include <onyx/page.h>

struct page_lru_batch
{
    unsigned int nr;
    struct page *batch[31];
};

struct percpu_batches
{
    struct local_lock lock;
    struct page_lru_batch lru_add;
    struct page_lru_batch activate;
};

static PER_CPU_VAR(struct percpu_batches lru_batches);

static inline int page_to_state(struct page *page)
{
    return page_flag_set(page, PAGE_FLAG_ANON) ? LRU_ANON_OFF : 0;
}

static unsigned int page_batch_add(struct page_lru_batch *batch, struct page *page)
{
    page_ref(page);
    batch->batch[batch->nr++] = page;
    return batch->nr - 31;
}

static void page_end_batch(struct page_lru_batch *batch)
{
    /* No locks should be held. Puts pages and clears the batch */
    for (unsigned int i = 0; i < batch->nr; i++)
        page_unref(batch->batch[i]);
    batch->nr = 0;
}

static void page_batch_add_lru(struct page_lru_batch *batch)
{
    struct page_lru *lru = NULL, *newlru;
    struct page *page;

    for (unsigned int i = 0; i < batch->nr; i++)
    {
        page = batch->batch[i];
        CHECK(!page_test_lru(page));
        newlru = page_to_page_lru(page);
        if (lru != newlru)
        {
            if (lru)
                spin_unlock(&lru->lock);
            spin_lock(&newlru->lock);
            lru = newlru;
        }

        page_set_lru(page);

        if (page_test_active(page))
        {
            /* We could be active before we're actually added to the LRU. In such case, add
             * ourselves directly to the active list. */
            inc_page_stat(page, NR_ACTIVE_FILE + page_to_state(page));
            list_add_tail(&page->lru_node, &lru->lru_lists[LRU_ACTIVE_BASE + page_to_state(page)]);
        }
        else
        {
            inc_page_stat(page, NR_INACTIVE_FILE + page_to_state(page));
            list_add_tail(&page->lru_node,
                          &lru->lru_lists[LRU_INACTIVE_BASE + page_to_state(page)]);
        }
    }

    spin_unlock(&lru->lock);
    page_end_batch(batch);
}

void page_add_lru(struct page *page)
{
    struct percpu_batches *batches = get_per_cpu_ptr(lru_batches);
    local_lock(&batches->lock);
    if (!page_batch_add(&batches->lru_add, page))
        page_batch_add_lru(&batches->lru_add);
    local_unlock(&batches->lock);
}

void page_remove_lru(struct page *page)
{
    CHECK(page_test_lru(page));
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

static void page_batch_activate_lru(struct page_lru_batch *batch)
{
    struct page_lru *lru = NULL, *newlru;
    struct page *page;

    for (unsigned int i = 0; i < batch->nr; i++)
    {
        page = batch->batch[i];
        CHECK(!page_test_lru(page));
        newlru = page_to_page_lru(page);
        if (lru != newlru)
        {
            if (lru)
                spin_unlock(&lru->lock);
            spin_lock(&newlru->lock);
            lru = newlru;
        }

        page_set_lru(page);

        if (!page_test_active(page))
        {
            list_remove(&page->lru_node);
            page_set_active(page);
            page_clear_referenced(page);
            dec_page_stat(page, NR_INACTIVE_FILE + page_to_state(page));
            inc_page_stat(page, NR_ACTIVE_FILE + page_to_state(page));
            list_add_tail(&page->lru_node, &lru->lru_lists[LRU_ACTIVE_BASE + page_to_state(page)]);
        }
    }

    spin_unlock(&lru->lock);
    page_end_batch(batch);
}

static void page_activate(struct page *page)
{
    struct percpu_batches *batches = get_per_cpu_ptr(lru_batches);

    if (!page_test_clear_lru(page))
    {
        /* We are *not* in the LRU. In this case, ignore the request to activate.
         * Adding us to the batch would wreak havoc if we indeed are not in the LRU by the time
         * page_batch_activate_lru runs. */
        return;
    }

    local_lock(&batches->lock);
    if (!page_batch_add(&batches->activate, page))
        page_batch_activate_lru(&batches->activate);
    local_unlock(&batches->lock);
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
    else
    {
        /* We're in a page batch (or bound to be added by someone else). Just set the active bit and
         * they'll take care of it. */
        page_set_active(page);
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
