/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/mm/kasan.h>
#include <onyx/mm/reclaim.h>
#include <onyx/mm/shrinker.h>
#include <onyx/mm/slab.h>
#include <onyx/page.h>
#include <onyx/rwlock.h>

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

        needed_bytes -= control.nr_freed * average_object_size;
    }

    rw_unlock_read(&shrinker_list_lock);
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
