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
    struct folio *batch[31];
};

struct percpu_batches
{
    struct local_lock lock;
    struct page_lru_batch lru_add;
    struct page_lru_batch activate;
    struct page_lru_batch deactivate;
};

static PER_CPU_VAR(struct percpu_batches lru_batches);

static inline int folio_to_state(struct folio *folio)
{
    return folio_test_anon(folio) ? LRU_ANON_OFF : 0;
}

static unsigned int folio_batch_add(struct page_lru_batch *batch, struct folio *folio)
{
    folio_get(folio);
    batch->batch[batch->nr++] = folio;
    return batch->nr - 31;
}

static void folio_end_batch(struct page_lru_batch *batch)
{
    /* No locks should be held. Puts pages and clears the batch */
    for (unsigned int i = 0; i < batch->nr; i++)
        folio_put(batch->batch[i]);
    batch->nr = 0;
}

#define folio_to_page_lru(folio) (page_to_page_lru(folio_to_page(folio)))

static void folio_batch_add_lru(struct page_lru_batch *batch)
{
    struct page_lru *lru = NULL, *newlru;
    struct folio *folio;

    for (unsigned int i = 0; i < batch->nr; i++)
    {
        folio = batch->batch[i];
        CHECK(!folio_test_lru(folio));
        newlru = folio_to_page_lru(folio);
        if (lru != newlru)
        {
            if (lru)
                spin_unlock(&lru->lock);
            spin_lock(&newlru->lock);
            lru = newlru;
        }

        folio_set_lru(folio);

        if (folio_test_active(folio))
        {
            /* We could be active before we're actually added to the LRU. In such case, add
             * ourselves directly to the active list. */
            inc_folio_stat(folio, NR_ACTIVE_FILE + folio_to_state(folio));
            list_add_tail(&folio->lru_node,
                          &lru->lru_lists[LRU_ACTIVE_BASE + folio_to_state(folio)]);
        }
        else
        {
            inc_folio_stat(folio, NR_INACTIVE_FILE + folio_to_state(folio));
            list_add_tail(&folio->lru_node,
                          &lru->lru_lists[LRU_INACTIVE_BASE + folio_to_state(folio)]);
        }
    }

    spin_unlock(&lru->lock);
    folio_end_batch(batch);
}

void folio_add_lru(struct folio *folio)
{
    struct percpu_batches *batches = get_per_cpu_ptr(lru_batches);
    local_lock(&batches->lock);
    if (!folio_batch_add(&batches->lru_add, folio))
        folio_batch_add_lru(&batches->lru_add);
    local_unlock(&batches->lock);
}

void folio_remove_lru(struct folio *folio)
{
    CHECK(folio_test_lru(folio));
    struct page_lru *lru = folio_to_page_lru(folio);
    spin_lock(&lru->lock);
    list_remove(&folio->lru_node);
    if (folio_test_active(folio))
        dec_folio_stat(folio, NR_ACTIVE_FILE + folio_to_state(folio));
    else
        dec_folio_stat(folio, NR_INACTIVE_FILE + folio_to_state(folio));
    folio_clear_lru(folio);
    spin_unlock(&lru->lock);
}

static void lru_remove_folio(struct page_lru *lru, struct folio *folio)
{
    /* Remove the folio from the lists, whilst maintaining the stats */
    list_remove(&folio->lru_node);
    if (folio_test_active(folio))
        dec_folio_stat(folio, NR_ACTIVE_FILE + folio_to_state(folio));
    else
        dec_folio_stat(folio, NR_INACTIVE_FILE + folio_to_state(folio));
}

static void lru_add_folio(struct page_lru *lru, struct folio *folio)
{
    /* Remove the folio from the lists, whilst maintaining the stats */
    if (folio_test_active(folio))
    {
        /* We could be active before we're actually added to the LRU. In such case, add
         * ourselves directly to the active list. */
        inc_folio_stat(folio, NR_ACTIVE_FILE + folio_to_state(folio));
        list_add_tail(&folio->lru_node, &lru->lru_lists[LRU_ACTIVE_BASE + folio_to_state(folio)]);
    }
    else
    {
        inc_folio_stat(folio, NR_INACTIVE_FILE + folio_to_state(folio));
        list_add_tail(&folio->lru_node, &lru->lru_lists[LRU_INACTIVE_BASE + folio_to_state(folio)]);
    }
}

static void folio_batch_activate_lru(struct page_lru_batch *batch)
{
    struct page_lru *lru = NULL, *newlru;
    struct folio *folio;

    for (unsigned int i = 0; i < batch->nr; i++)
    {
        folio = batch->batch[i];
        CHECK(!folio_test_lru(folio));
        newlru = folio_to_page_lru(folio);
        if (lru != newlru)
        {
            if (lru)
                spin_unlock(&lru->lock);
            spin_lock(&newlru->lock);
            lru = newlru;
        }

        folio_set_lru(folio);

        if (!folio_test_active(folio))
        {
            list_remove(&folio->lru_node);
            folio_set_active(folio);
            folio_clear_referenced(folio);
            dec_folio_stat(folio, NR_INACTIVE_FILE + folio_to_state(folio));
            inc_folio_stat(folio, NR_ACTIVE_FILE + folio_to_state(folio));
            list_add_tail(&folio->lru_node,
                          &lru->lru_lists[LRU_ACTIVE_BASE + folio_to_state(folio)]);
        }
    }

    spin_unlock(&lru->lock);
    folio_end_batch(batch);
}

static void folio_activate(struct folio *folio)
{
    struct percpu_batches *batches = get_per_cpu_ptr(lru_batches);

    if (!folio_test_clear_lru(folio))
    {
        /* We are *not* in the LRU. In this case, ignore the request to activate.
         * Adding us to the batch would wreak havoc if we indeed are not in the LRU by the time
         * page_batch_activate_lru runs. */
        return;
    }

    local_lock(&batches->lock);
    if (!folio_batch_add(&batches->activate, folio))
        folio_batch_activate_lru(&batches->activate);
    local_unlock(&batches->lock);
}

void folio_promote_referenced(struct folio *folio)
{
    /* Promote a page in the page LRUs. We go from (considering Active, Referenced) (0,0) -> (0, 1)
     * -> (1, 0) -> (1, 1). In reality we could interpret this as a generation counter. Some slight
     * imprecision is tolerated, so we can skip all sorts of awful locking or cmpxchg stuff we would
     * need to pull off. */
    if (!folio_test_referenced(folio))
    {
        /* go from unref'd, inactive to ref'd, inactive */
        folio_set_referenced(folio);
    }
    else if (folio_test_lru(folio))
    {
        /* Referenced, activate. Note that we only try to activate if the page is in the LRU system
         * yet. If not, ignore. Trying to activate a page that's not quite in LRU yet will lead to
         * races. */
        folio_activate(folio);
    }
    else
    {
        /* We're in a page batch (or bound to be added by someone else). Just set the active bit and
         * they'll take care of it. */
        folio_set_active(folio);
    }
}

static void folio_batch_deactivate_lru(struct page_lru_batch *batch)
{
    struct page_lru *lru = NULL, *newlru;
    struct folio *folio;

    for (unsigned int i = 0; i < batch->nr; i++)
    {
        folio = batch->batch[i];
        CHECK(!folio_test_lru(folio));
        newlru = folio_to_page_lru(folio);
        if (lru != newlru)
        {
            if (lru)
                spin_unlock(&lru->lock);
            spin_lock(&newlru->lock);
            lru = newlru;
        }

        lru_remove_folio(lru, folio);
        folio_set_lru(folio);
        folio_clear_active(folio);
        folio_clear_referenced(folio);
        lru_add_folio(lru, folio);
    }

    spin_unlock(&lru->lock);
    folio_end_batch(batch);
}

void page_lru_demote_reclaim(struct folio *folio)
{
    struct percpu_batches *batches = get_per_cpu_ptr(lru_batches);

    if (folio_test_dirty(folio) || folio_test_locked(folio))
        return;

    if (!folio_test_clear_lru(folio))
        return;

    local_lock(&batches->lock);
    if (!folio_batch_add(&batches->deactivate, folio))
        folio_batch_deactivate_lru(&batches->deactivate);
    local_unlock(&batches->lock);
}
