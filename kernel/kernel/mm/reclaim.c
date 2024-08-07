/*
 * Copyright (c) 2023 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>

#include <onyx/mm/kasan.h>
#include <onyx/mm/page_node.h>
#include <onyx/mm/reclaim.h>
#include <onyx/mm/shrinker.h>
#include <onyx/mm/slab.h>
#include <onyx/mm/vm_object.h>
#include <onyx/page.h>
#include <onyx/rwlock.h>
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
};

#ifdef __clang__
#pragma GCC diagnostic pop
#endif

#undef X

static void dump_page(struct page *page)
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
    if (page->owner)
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

static enum lru_result shrink_page(struct page *page)
{
    DCHECK_PAGE(page->owner, page);
    if (!try_lock_page(page))
        return LRU_ROTATE;
    struct vm_object *obj = page->owner;
    unsigned int vm_flags = 0;

    long refs = vm_obj_get_page_references(obj, page, &vm_flags);
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
        if (page_flag_set(page, PAGE_FLAG_REFERENCED))
            return LRU_ACTIVATE;
        page_set_flag(page, PAGE_FLAG_REFERENCED);
        return LRU_ROTATE;
    }

    if (page_flag_set(page, PAGE_FLAG_REFERENCED) || page_flag_set(page, PAGE_FLAG_DIRTY))
    {
        __atomic_and_fetch(&page->flags, ~PAGE_FLAG_REFERENCED, __ATOMIC_RELAXED);
        unlock_page(page);
        return LRU_ROTATE;
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
    DCHECK(page->ref == 1);
    dec_page_stat(page, NR_FILE);
    dec_page_stat(page, NR_INACTIVE_FILE);
    list_remove(&page->lru_node);
    __atomic_and_fetch(&page->flags, ~PAGE_FLAG_LRU, __ATOMIC_RELAXED);
    if (obj->ops->free_page)
        obj->ops->free_page(obj, page);
    else
        free_page(page);
    return LRU_SHRINK;
}

#define DEBUG_SHRINK_ZONE 1

static unsigned long inactive_file_min(const unsigned long stats[PAGE_STATS_MAX])
{
    /* Target at least 1/4 of the total page cache as the inactive list's size */
    return (stats[NR_INACTIVE_FILE] + stats[NR_ACTIVE_FILE]) / 4;
}

static void shrink_active_list(struct page_node *node, struct page_zone *zone,
                               const unsigned long pagestats[PAGE_STATS_MAX],
                               unsigned long target_inactive)
{
    /* Attempt to shrink the active list such that we hit target_inactive */
    struct page_lru *lru = &zone->zone_lru;
    spin_lock(&lru->lock);
    DCHECK(target_inactive > pagestats[NR_INACTIVE_FILE]);
    unsigned long to_move = target_inactive - pagestats[NR_INACTIVE_FILE];
    list_for_every_safe (&lru->lru_lists[LRU_ACTIVE])
    {
        if (to_move-- == 0)
            break;
        struct page *page = container_of(l, struct page, lru_node);
        /* Referenced? rotate it back to the list's tail. If we're really desperate for inactive
         * pages, we'll be able to fetch again, no problem. */
        if (page_flag_set(page, PAGE_FLAG_REFERENCED))
        {
            __atomic_and_fetch(&page->flags, ~PAGE_FLAG_REFERENCED, __ATOMIC_RELAXED);
            list_remove(&page->lru_node);
            list_add_tail(&page->lru_node, &lru->lru_lists[LRU_ACTIVE]);
            continue;
        }

        list_remove(&page->lru_node);
        list_add_tail(&page->lru_node, &lru->lru_lists[LRU_INACTIVE]);
        dec_page_stat(page, NR_ACTIVE_FILE);
        inc_page_stat(page, NR_INACTIVE_FILE);
    }

    spin_unlock(&lru->lock);
}

static void shrink_zone(struct reclaim_data *data, struct page_node *node, struct page_zone *zone,
                        unsigned long target_freep)
{
    unsigned long target = target_freep;
    unsigned long stats[PAGE_STATS_MAX];
    page_accumulate_stats(stats);
    (void) target;
    struct page_lru *lru = &zone->zone_lru;
    DEFINE_LIST(rotate_list);
    DEFINE_LIST(activate_list);

    unsigned long min_inactive = inactive_file_min(stats);
    if (stats[NR_INACTIVE_FILE] < min_inactive)
        shrink_active_list(node, zone, stats, min_inactive);
    spin_lock(&lru->lock);

    list_for_every_safe (&lru->lru_lists[LRU_INACTIVE])
    {
        struct page *page = container_of(l, struct page, lru_node);
        enum lru_result res = shrink_page(page);
        if (res == LRU_ROTATE)
        {
            list_remove(&page->lru_node);
            list_add_tail(&page->lru_node, &rotate_list);
        }
        else if (res == LRU_SHRINK)
        {
            target_freep--;
            if (target_freep == 0)
                break;
        }
        else if (res == LRU_ACTIVATE)
        {
            list_remove(&page->lru_node);
            list_add_tail(&page->lru_node, &activate_list);
        }
    }

#ifdef DEBUG_SHRINK_ZONE
    pr_warn("shrink_zone: Zone %s freed %lu pages (out of %lu)\n", zone->name,
            target - target_freep, target);
    pr_warn("shrink_zone: inactive %lu active %lu\n", stats[NR_INACTIVE_FILE],
            stats[NR_ACTIVE_FILE]);
#endif
    list_splice(&rotate_list, &lru->lru_lists[LRU_INACTIVE]);
    list_for_every_safe (&activate_list)
    {
        /* TODO: We're doing this in the wrong place... */
        struct page *page = container_of(l, struct page, lru_node);
        list_remove(&page->lru_node);
        page_set_flag(page, PAGE_FLAG_ACTIVE);
        dec_page_stat(page, NR_INACTIVE_FILE);
        inc_page_stat(page, NR_ACTIVE_FILE);
        __atomic_and_fetch(&page->flags, ~PAGE_FLAG_REFERENCED, __ATOMIC_RELEASE);
        list_add_tail(&page->lru_node, &lru->lru_lists[LRU_ACTIVE]);
    }

    spin_unlock(&lru->lock);
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

    while ((free_target = pages_under_high_watermark()) > 0)
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
