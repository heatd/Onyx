/*
 * Copyright (c) 2023 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>

#include <onyx/filemap.h>
#include <onyx/mm/kasan.h>
#include <onyx/mm/page_node.h>
#include <onyx/mm/reclaim.h>
#include <onyx/mm/shrinker.h>
#include <onyx/mm/slab.h>
#include <onyx/mm/vm_object.h>
#include <onyx/page.h>
#include <onyx/rmap.h>
#include <onyx/rwlock.h>
#include <onyx/swap.h>
#include <onyx/vfs.h>

static struct list_head shrinker_list = LIST_HEAD_INIT(shrinker_list);
static struct rwlock shrinker_list_lock;

void shrinker_register(struct shrinker *shr)
{
    rw_lock_write(&shrinker_list_lock);
    list_add_tail(&shr->list_node, &shrinker_list);
    rw_unlock_write(&shrinker_list_lock);
}

void shrinker_unregister(struct shrinker *shr)
{
    rw_lock_write(&shrinker_list_lock);
    list_remove(&shr->list_node);
    rw_unlock_write(&shrinker_list_lock);
}

/**
 * @brief Shrink object caches
 *
 * @param data Data associated with this reclaim
 * @param free_page_target Target of pages to free
 */
static void shrink_objects(struct reclaim_data *data, unsigned long free_page_target)
{
    rw_lock_read(&shrinker_list_lock);

    /* To make this logic cheaper, we sort of estimate how large each object is and take it off
     * free_page_target based on that.
     */
    long needed_bytes = free_page_target;

    list_for_every (&shrinker_list)
    {
        struct shrinker *shrinker = container_of(l, struct shrinker, list_node);
        struct shrink_control control;

        /* We give scan_objects the number of pages we want, and the shrinker will then estimate how
         * many pages will get released by each object, and properly adjust target_objs.
         */

        if (needed_bytes <= 0)
            break;

        free_page_target = needed_bytes >> PAGE_SHIFT;
        control.nr_freed = 0;
        control.target_objs = free_page_target;
        control.gfp_flags = data->gfp_flags;

        /* First, count the number of objects we do have */
        int st = shrinker->scan_objects(shrinker, &control);

        /* Shrinker cannot do it's job, just continue */
        if (st == SHRINK_STOP || control.target_objs == 0)
            continue;

        unsigned long average_object_size = needed_bytes / control.target_objs;

        st = shrinker->shrink_objects(shrinker, &control);

        if (st == SHRINK_STOP)
            continue;

        pr_info("shrinker %s freed %lu objects\n", shrinker->name, control.nr_freed);
        needed_bytes -= control.nr_freed * average_object_size;
    }

    rw_unlock_read(&shrinker_list_lock);
}

enum lru_result
{
    LRU_SHRINK,
    LRU_ROTATE,
    LRU_ACTIVATE
};

#ifdef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstring-plus-int"
#endif

struct page_flag
{
    unsigned long val;
    const char *name;
};

/* 10 = strlen(PAGE_FLAG_) */
#define X(macro)                          \
    {                                     \
        .val = macro, .name = #macro + 10 \
    }

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static const struct page_flag flags[] = {
    X(PAGE_FLAG_LOCKED),      X(PAGE_FLAG_DIRTY),
    X(PAGE_FLAG_PINNED),      {.val = PAGE_BUDDY, .name = "BUDDY"},
    X(PAGE_FLAG_BUFFER),      X(PAGE_FLAG_ANON),
    X(PAGE_FLAG_FILESYSTEM1), X(PAGE_FLAG_WAITERS),
    X(PAGE_FLAG_UPTODATE),    X(PAGE_FLAG_WRITEBACK),
    X(PAGE_FLAG_READAHEAD),   X(PAGE_FLAG_LRU),
    X(PAGE_FLAG_REFERENCED),  X(PAGE_FLAG_ACTIVE),
    X(PAGE_FLAG_SWAP),        X(PAGE_FLAG_RECLAIM),
};

#ifdef __clang__
#pragma GCC diagnostic pop
#endif

#undef X

void dump_page(struct page *page)
{
    char flags_buf[128];
    char *b = flags_buf;
    size_t len = 128;
    bool first = true;
    flags_buf[0] = 0;

    for (unsigned int i = 0; i < ARRAY_SIZE(flags); i++)
    {
        if (page->flags & flags[i].val)
        {
            if (!first)
            {
                if (len > 2)
                    *b = '|', b++, *b = '\0', len--;
            }

            size_t copied = strlcpy(b, flags[i].name, len);
            len -= copied;
            b += copied;
            first = false;
        }
    }

    pr_crit("Page %p (pfn %016lx)  ref: %u mapcount: %u (%u)\n", page, page_to_pfn(page), page->ref,
            page->mapcount, page_mapcount(page));
    pr_crit("  flags: %016lx (%s)  private: %016lx\n", page->flags, flags_buf, page->priv);
    pr_crit("  owner: %p  pageoff %lx\n", page->owner, page->pageoff);
    if (page->owner && !page_flag_set(page, PAGE_FLAG_ANON))
    {
        struct inode *inode = page->owner->ino;
        pr_crit("  owner vm_obj_ops: %ps  inode num %lu dev %lu\n", page->owner->ops,
                inode->i_inode, inode->i_dev);
    }
}

void bug_on_page(struct page *page, const char *expr, const char *file, unsigned int line,
                 const char *func)
{
    pr_crit("Assertion %s failed in %s:%u, in function %s\n", expr, file, line, func);
    dump_page(page);
    panic(expr);
}

#define DCHECK_PAGE(expr, page) \
    if (unlikely(!(expr)))      \
        bug_on_page(page, #expr, __FILE__, __LINE__, __func__);

enum pageout_result
{
    PAGE_ACTIVATE = 0,
    PAGE_WRITTEN,
    PAGE_ROTATE
};

static bool may_writeout(struct reclaim_data *data, struct page *page)
{
    /* Check if we can writeout the page. We'll assume all normal file page writeback is __GFP_FS,
     * and all swap IO is __GFP_IO. */
    if (data->gfp_flags & __GFP_FS)
        return true;
    if (!page_test_swap(page) || !(data->gfp_flags & __GFP_IO))
        return false;
    return true;
}

static enum pageout_result pageout(struct reclaim_data *data, struct page *page,
                                   struct vm_object *obj) REQUIRES(page)
    RELEASE(page) NO_THREAD_SAFETY_ANALYSIS
{
    if (!may_writeout(data, page))
        return PAGE_ROTATE;

    if (!obj->ops->writepage)
        return PAGE_ACTIVATE;
    filemap_clear_dirty(page);
    ssize_t st = obj->ops->writepage(obj, page, page_pgoff(page) << PAGE_SHIFT);
    if (st < 0)
        pr_warn("pageout %p off %lx callback %pS = %zd\n", page, page->pageoff, obj->ops->writepage,
                st);
    return PAGE_WRITTEN;
}

static enum lru_result shrink_page(struct reclaim_data *data,
                                   struct page *page) NO_THREAD_SAFETY_ANALYSIS
{
    if (!try_lock_page(page))
        return LRU_ROTATE;

    if (page_test_swap(page) && !page->owner)
    {
        /* Huh. Incomplete swapcache page? Skip. */
        goto rotate;
    }

    DCHECK_PAGE(page->owner, page);
    struct vm_object *obj;
    unsigned int vm_flags = 0;

    long refs = rmap_get_page_references(page, &vm_flags);
    /* Always activate executable pages or (actively) shared pages */
    if (vm_flags & VM_EXEC || refs > 1)
    {
        unlock_page(page);
        return LRU_ACTIVATE;
    }

    /* Give the page another round if refs = 1 (a single A bit was found) or if referenced was set.
     * Also give it another round if dirty, because we can't writeback in reclaim (yet?) and it's an
     * indicative of page activity anyway. */

    if (refs > 0)
    {
        /* Activate a referenced page with pte refs, or reference it if not referenced yet */
        unlock_page(page);
        if (page_test_referenced(page))
            return LRU_ACTIVATE;
        page_set_referenced(page);
        return LRU_ROTATE;
    }

    if (page_test_referenced(page))
    {
        page_clear_referenced(page);
        goto rotate;
    }

    if (page_flag_set(page, PAGE_FLAG_ANON) && !page_test_swap(page))
    {
        int err = swap_add(page);
        if (err < 0)
            goto rotate;
    }

    /* Set RECLAIM. If we have to bail the reclaim (because e.g it is dirty), certain code points
     * will know to demote the page back to INACTIVE head, so we look at it again (hopefully
     * clean). */

    rmap_try_to_unmap(page);

    if (page_mapcount(page) > 0)
    {
        /* We failed to unmap it all :( Rotate the page */
        goto rotate;
    }

    if (page_flag_set(page, PAGE_FLAG_ANON))
        WARN_ON(!page_test_swap(page));

    page_set_reclaim(page);

    obj = page_vmobj(page);
    if (page_flag_set(page, PAGE_FLAG_DIRTY))
    {
        enum pageout_result res = pageout(data, page, obj);
        switch (res)
        {
            case PAGE_ROTATE: {
                goto rotate;
            }

            case PAGE_ACTIVATE: {
                unlock_page(page);
                return LRU_ACTIVATE;
            }

            case PAGE_WRITTEN: {
                /* Check if the write was synchronous, or if it somehow has completed already. If
                 * so, try to reclaim it synchronously. */
                if (page_flag_set(page, PAGE_FLAG_DIRTY))
                    goto rotate_unlocked;
                if (page_flag_set(page, PAGE_FLAG_WRITEBACK))
                    goto rotate_unlocked;

                if (!try_lock_page(page))
                    goto rotate_unlocked;

                /* Repeat these checks */
                if (page_flag_set(page, PAGE_FLAG_DIRTY) ||
                    page_flag_set(page, PAGE_FLAG_WRITEBACK))
                    goto rotate;

                /* We can reclaim it, keep going! */
                break;
            }
        }
    }

    /* This should be a stable reference. TODO: What if truncation? What if the inode goes away
     * after the unlock? */
    // pr_info("removing page %p\n", page);
    if (!vm_obj_remove_page(obj, page))
    {
        /* If we failed to remove the page, it's busy */
        unlock_page(page);
        return LRU_ROTATE;
    }

    unlock_page(page);
    DCHECK(page->ref == 2);
    page_unref(page);
    if (!page_flag_set(page, PAGE_FLAG_ANON))
        dec_page_stat(page, NR_FILE);

    list_remove(&page->lru_node);
    page_clear_lru(page);
    page_clear_swap(page);
    if (obj->ops->free_page)
        obj->ops->free_page(obj, page);
    else
        free_page(page);
    return LRU_SHRINK;
rotate:
    unlock_page(page);
rotate_unlocked:
    return LRU_ROTATE;
}

#undef DEBUG_SHRINK_ZONE

static unsigned long inactive_file_min(const unsigned long stats[PAGE_STATS_MAX])
{
    /* Target at least 1/4 of the total page cache as the inactive list's size */
    return (stats[NR_INACTIVE_FILE] + stats[NR_ACTIVE_FILE]) / 4;
}

static unsigned long inactive_anon_min(const unsigned long stats[PAGE_STATS_MAX])
{
    /* Target at least 1/4 of the total anon as the inactive list's size */
    return (stats[NR_INACTIVE_ANON] + stats[NR_ACTIVE_ANON]) / 4;
}

static void shrink_active_list(struct page_node *node, enum lru_state lru_list,
                               struct page_zone *zone,
                               const unsigned long pagestats[PAGE_STATS_MAX],
                               unsigned long target_inactive)
{
    /* Attempt to shrink the active list such that we hit target_inactive */
    struct page_lru *lru = &zone->zone_lru;
    enum lru_state inactive = lru_list - 1;
    spin_lock(&lru->lock);
    DCHECK(target_inactive > pagestats[NR_INACTIVE_FILE + inactive]);
    unsigned long to_move = target_inactive - pagestats[NR_INACTIVE_FILE + inactive];
    list_for_every_safe (&lru->lru_lists[lru_list])
    {
        if (to_move-- == 0)
            break;
        struct page *page = container_of(l, struct page, lru_node);
        /* Referenced? rotate it back to the list's tail. If we're really desperate for inactive
         * pages, we'll be able to fetch again, no problem. */
        if (page_flag_set(page, PAGE_FLAG_REFERENCED))
        {
            page_clear_referenced(page);
            list_remove(&page->lru_node);
            list_add_tail(&page->lru_node, &lru->lru_lists[lru_list]);
            continue;
        }

        list_remove(&page->lru_node);
        list_add_tail(&page->lru_node, &lru->lru_lists[inactive]);
        dec_page_stat(page, NR_INACTIVE_FILE + lru_list);
        inc_page_stat(page, NR_INACTIVE_FILE + inactive);
    }

    spin_unlock(&lru->lock);
}

static inline int page_to_state(struct page *page)
{
    return page_flag_set(page, PAGE_FLAG_ANON) ? LRU_ANON_OFF : 0;
}

static void isolate_pages(struct page_lru *lru, enum lru_state list, struct list_head *page_list,
                          unsigned long nr_pages)
{
    DEFINE_LIST(rotate_list);
    list_for_every_safe (&lru->lru_lists[list])
    {
        struct page *page = container_of(l, struct page, lru_node);
        if (page_flag_set(page, PAGE_FLAG_REFERENCED))
        {
            /* Rotate it (dont even attempt to isolate the page) */
            page_clear_referenced(page);
            list_remove(&page->lru_node);
            list_add_tail(&page->lru_node, &rotate_list);
            continue;
        }

        /* Not sure if we need a page_try_get here... */
        page_ref(page);
        DCHECK(page->ref > 1);
        page_clear_lru(page);
        list_remove(&page->lru_node);
        dec_page_stat(page, NR_INACTIVE_FILE + page_to_state(page));
        list_add_tail(&page->lru_node, page_list);
        if (--nr_pages == 0)
            break;
    }

    list_splice(&rotate_list, &lru->lru_lists[list]);
}

struct pagebatch
{
    struct page *batch[32];
    int nr;
};

static bool page_batch_add(struct pagebatch *batch, struct page *page)
{
    batch->batch[batch->nr++] = page;
    return batch->nr == 32;
}

static void page_unref_batch(struct pagebatch *batch)
{
    /* LRU lock *is not held* */
    for (int i = 0; i < batch->nr; i++)
        page_unref(batch->batch[i]);
    batch->nr = 0;
}

static unsigned long shrink_page_list(struct reclaim_data *data, struct page_lru *lru,
                                      struct list_head *page_list)
{
    DEFINE_LIST(rotate_list);
    DEFINE_LIST(activate_list);
    struct pagebatch free_batch;
    unsigned long freedp = 0;

    free_batch.nr = 0;
    list_for_every_safe (page_list)
    {
        struct page *page = container_of(l, struct page, lru_node);
        DCHECK_PAGE(!page_flag_set(page, PAGE_FLAG_LRU), page);
        enum lru_result res = shrink_page(data, page);
        if (res == LRU_ROTATE)
        {
            list_remove(&page->lru_node);
            list_add_tail(&page->lru_node, &rotate_list);
        }
        else if (res == LRU_SHRINK)
            freedp++;
        else if (res == LRU_ACTIVATE)
        {
            list_remove(&page->lru_node);
            list_add_tail(&page->lru_node, &activate_list);
        }
    }

    if (list_is_empty(&rotate_list) && list_is_empty(&activate_list))
        goto out;

    spin_lock(&lru->lock);
    list_for_every_safe (&rotate_list)
    {
        struct page *page = container_of(l, struct page, lru_node);
        list_remove(&page->lru_node);
        list_add_tail(&page->lru_node, &lru->lru_lists[LRU_INACTIVE_FILE + page_to_state(page)]);
        page_set_lru(page);
        inc_page_stat(page, NR_INACTIVE_FILE + page_to_state(page));
        if (page_batch_add(&free_batch, page))
        {
            spin_unlock(&lru->lock);
            page_unref_batch(&free_batch);
            spin_lock(&lru->lock);
        }
    }

    list_for_every_safe (&activate_list)
    {
        struct page *page = container_of(l, struct page, lru_node);
        list_remove(&page->lru_node);
        page_set_flag(page, PAGE_FLAG_ACTIVE);
        inc_page_stat(page, NR_ACTIVE_FILE + page_to_state(page));
        page_clear_referenced(page);
        list_add_tail(&page->lru_node, &lru->lru_lists[LRU_ACTIVE_FILE + page_to_state(page)]);
        if (page_batch_add(&free_batch, page))
        {
            spin_unlock(&lru->lock);
            page_unref_batch(&free_batch);
            spin_lock(&lru->lock);
        }
    }

    spin_unlock(&lru->lock);
    page_unref_batch(&free_batch);
out:
    return freedp;
}

static unsigned long isolate_and_shrink(struct reclaim_data *data, enum lru_state lru_list,
                                        struct page_lru *lru, unsigned long nr)
{
    DEFINE_LIST(isolate_list);
    if (!nr)
        return 0;

    spin_lock(&lru->lock);
    isolate_pages(lru, lru_list, &isolate_list, nr);
    spin_unlock(&lru->lock);

    return shrink_page_list(data, lru, &isolate_list);
}

static void calculate_scan(unsigned long stats[PAGE_STATS_MAX])
{
    bool has_swap = swap_is_available();
    unsigned int file_ratio = has_swap ? 2 : 1;
    stats[NR_INACTIVE_FILE] /= file_ratio;
    if (has_swap)
        stats[NR_INACTIVE_ANON] /= 2;
    else
        stats[NR_INACTIVE_ANON] = 0;
}

#define SWAP_CLUSTER_MAX 64UL

static void shrink_zone(struct reclaim_data *data, struct page_node *node, struct page_zone *zone,
                        long target_freep)
{
    unsigned long stats[PAGE_STATS_MAX];
    page_accumulate_stats(stats);
    struct page_lru *lru = &zone->zone_lru;

    unsigned long min_inactive = inactive_file_min(stats);
    unsigned long min_inactive_anon = inactive_anon_min(stats);
    if (stats[NR_INACTIVE_FILE] < min_inactive)
        shrink_active_list(node, LRU_ACTIVE_FILE, zone, stats, min_inactive);
    if (stats[NR_INACTIVE_ANON] < min_inactive_anon)
        shrink_active_list(node, LRU_ACTIVE_ANON, zone, stats, min_inactive_anon);

    page_accumulate_stats(stats);
    calculate_scan(stats);

    while (target_freep > 0)
    {
        unsigned long nr_file = min(stats[NR_INACTIVE_FILE], SWAP_CLUSTER_MAX);
        unsigned nr_anon = min(stats[NR_INACTIVE_ANON], SWAP_CLUSTER_MAX);
        if (!nr_file && !nr_anon)
            break;

        stats[NR_INACTIVE_FILE] -= nr_file;
        stats[NR_INACTIVE_ANON] -= nr_anon;

        unsigned long freed = isolate_and_shrink(data, LRU_INACTIVE_FILE, lru, nr_file);
        data->nr_reclaimed += freed;
        target_freep -= freed;
        freed = isolate_and_shrink(data, LRU_INACTIVE_ANON, lru, nr_anon);
        data->nr_reclaimed += freed;
        target_freep -= freed;
    }

#ifdef DEBUG_SHRINK_ZONE
    pr_warn("shrink_zone: Zone %s freed %lu pages (out of %lu)\n", zone->name, freed, target_freep);
    pr_warn("shrink_zone: inactive %lu active %lu\n", stats[NR_INACTIVE_FILE],
            stats[NR_ACTIVE_FILE]);
#endif
}

static void shrink_page_zones(struct reclaim_data *data, struct page_node *node)
{
    struct page_zone *zone;
    for_zones_in_node(node, zone)
    {
        unsigned long freep = zone->total_pages - zone->used_pages;
        unsigned long target = 0;

        if (freep <= zone->low_watermark)
            target = zone->high_watermark - freep;

        /* This logic is weird and leaky (we don't get nearly as many details from
         * page_reclaim_target as we'd wish), but it should do the job. Get 1.5 * max(order, 3)% of
         * the zone free.
         */
        if (target == 0 && data->failed_order > 0)
            target = (zone->total_pages / 66) * max(data->failed_order, 3);

        if (target == 0)
            continue;

        shrink_zone(data, node, zone, target);
    }
}

/**
 * @brief Do (direct?) page reclamation. Called from direct reclaim or pagedaemon.
 *
 * @param data Data associated with this reclaim.
 *
 * @return 0 on success, -1 if we failed to go over the high watermark
 */
int page_do_reclaim(struct reclaim_data *data)
{
    /* Let's retry all this based on our desperation */
    unsigned long free_target;
    int max_tries = data->attempt > 0 ? 5 : 3;
    int nr_tries = 0;

    while ((free_target = page_reclaim_target(data->gfp_flags, data->failed_order)) > 0)
    {
        if (nr_tries == max_tries)
            return -1;
        /* Lets scale according to our desperation */
        if (nr_tries > 0)
            free_target *= nr_tries;
        shrink_page_zones(data, &main_node);
        shrink_objects(data, free_target);
#ifdef CONFIG_KASAN
        /* KASAN is likely to have a lot of objects under its wing, so flush it. */
        kasan_flush_quarantine();
#endif
        /* After (possibly!) flushing the KASAN quaratine, shrink slab caches's free slabs */
        slab_shrink_caches(free_target);
        /* After shrinking slabs, drain pcpu lists */
        page_drain_pcpu();

        nr_tries++;
    }

    return 0;
}

#ifdef CONFIG_SHRINKER_TEST

int nr_shrunk = 0;

namespace
{

struct test_obj
{
    unsigned long a[80];
    struct list_head list_node;
};

struct list_head object_list = LIST_HEAD_INIT(object_list);
unsigned long nr_objects;
struct spinlock object_list_lock;

int test_scan_objects(struct shrinker *shr, struct shrink_control *ctl)
{
    ctl->target_objs = (ctl->target_objs * PAGE_SIZE) / sizeof(struct test_obj);
    return 0;
}

int test_shrink_objects(struct shrinker *shr, struct shrink_control *ctl)
{
    spin_lock(&object_list_lock);

    list_for_every_safe (&object_list)
    {
        if (ctl->nr_freed == ctl->target_objs)
            break;

        struct test_obj *obj = container_of(l, struct test_obj, list_node);
        list_remove(&obj->list_node);
        kfree(obj);
        nr_objects--;
        ctl->nr_freed++;
    }

    nr_shrunk++;
    spin_unlock(&object_list_lock);

    return 0;
}

void test_add_object()
{
    struct test_obj *obj = (struct test_obj *) kmalloc(sizeof(*obj), GFP_KERNEL);
    CHECK(obj != nullptr);
    spin_lock(&object_list_lock);

    list_add_tail(&obj->list_node, &object_list);
    nr_objects++;

    spin_unlock(&object_list_lock);
}

void shrinker_do_stress_test()
{
    for (;;)
    {
        test_add_object();
    }
}

} // namespace

void shrinker_test()
{
    struct shrinker shr;
    shr.name = "shrinker_test";
    shr.flags = 0;
    shr.scan_objects = test_scan_objects;
    shr.shrink_objects = test_shrink_objects;
    shrinker_register(&shr);

    shrinker_do_stress_test();

    shrinker_unregister(&shr);
}

#endif
