/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>

#include <onyx/compiler.h>
#include <onyx/mm/slab.h>
#include <onyx/mm/vm_object.h>
#include <onyx/page.h>
#include <onyx/rmap.h>

static struct slab_cache *anon_vma_cache;

static void anon_vma_ctor(void *ctor)
{
    struct anon_vma *vma = ctor;
    spinlock_init(&vma->lock);
    INIT_LIST_HEAD(&vma->vma_list);
}

void __init anon_vma_init(void)
{
    anon_vma_cache =
        kmem_cache_create("anon_vma", sizeof(struct anon_vma), _Alignof(struct anon_vma),
                          KMEM_CACHE_PANIC | SLAB_TYPESAFE_BY_RCU, anon_vma_ctor);
}

struct anon_vma *anon_vma_alloc(void)
{
    return kmem_cache_alloc(anon_vma_cache, GFP_KERNEL);
}

void __anon_vma_unlink(struct anon_vma *anon, struct vm_area_struct *vma)
{
    bool free = false;
    list_remove(&vma->anon_vma_node);
    free = list_is_empty(&anon->vma_list);
    if (free)
        kmem_cache_free(anon_vma_cache, anon);
}

void anon_vma_unlink(struct anon_vma *anon, struct vm_area_struct *vma)
{
    bool free = false;
    spin_lock(&anon->lock);

    list_remove(&vma->anon_vma_node);
    free = list_is_empty(&anon->vma_list);
    spin_unlock(&anon->lock);

    if (free)
        kmem_cache_free(anon_vma_cache, anon);
}

struct anon_vma *anon_vma_prepare(struct vm_area_struct *vma)
{
    struct anon_vma *anon_vma = READ_ONCE(vma->anon_vma);
    if (likely(anon_vma))
        return anon_vma;

    /* We need to create a fresh anon_vma and add ourselves to it. We can race with other threads,
     * so we'll use page_tables_lock as our exclusion mechanism. */
    anon_vma = anon_vma_alloc();
    if (!anon_vma)
        return NULL;

    spin_lock(&vma->vm_mm->page_table_lock);

    if (!vma->anon_vma)
    {
        /* We don't need the anon_vma lock here, as we haven't published this anon_vma out to the
         * wild yet  */
        list_add_tail(&vma->anon_vma_node, &anon_vma->vma_list);
        __atomic_store_n(&vma->anon_vma, anon_vma, __ATOMIC_RELEASE);
    }
    else
    {
        kmem_cache_free(anon_vma_cache, anon_vma);
        anon_vma = vma->anon_vma;
        DCHECK(anon_vma != NULL);
    }

    spin_unlock(&vma->vm_mm->page_table_lock);

    return anon_vma;
}

void __anon_vma_link(struct anon_vma *anon, struct vm_area_struct *vma)
{
    list_add_tail(&vma->anon_vma_node, &anon->vma_list);
}

void anon_vma_link(struct anon_vma *anon, struct vm_area_struct *vma)
{
    spin_lock(&anon->lock);
    __anon_vma_link(anon, vma);
    spin_unlock(&anon->lock);
}

struct rmap_walk_info
{
    int (*walk_one)(struct vm_area_struct *vma, struct page *page, unsigned long addr,
                    void *context);
    void *context;
};

static struct anon_vma *anon_vma_lock(struct page *page)
{
    /* We use RCU read lock and TYPESAFE_BY_RCU to get by here. The idea goes like this: We check if
     * page_mapcount != 0 under the rcu_read_lock; if this is true, the anon_vma struct _must_ be
     * valid. We then spin_lock the anon_vma (which only works because TYPESAFE_BY_RCU and the read
     * lock enforce type stability here). We then recheck the mapcount under the lock. */
    struct anon_vma *anon_vma;
    rcu_read_lock();
    anon_vma = (struct anon_vma *) READ_ONCE(page->owner);
    if (!page_mapcount(page))
        goto no_anon_vma;

    spin_lock(&anon_vma->lock);
    if (!page_mapcount(page))
    {
        spin_unlock(&anon_vma->lock);
        goto no_anon_vma;
    }

    rcu_read_unlock();
    return anon_vma;
no_anon_vma:
    rcu_read_unlock();
    return NULL;
}

static int rmap_walk_anon(struct rmap_walk_info *info, struct page *page)
{
    DCHECK_PAGE(page_flag_set(page, PAGE_FLAG_ANON), page);
    struct anon_vma *anon_vma = anon_vma_lock(page);
    if (!anon_vma)
        return 0;

    unsigned long page_addr = page->pageoff;
    int st = 0;

    list_for_every (&anon_vma->vma_list)
    {
        struct vm_area_struct *vma = container_of(l, struct vm_area_struct, anon_vma_node);
        /* Check if the vma does cover the page (we stash the addr in pgoff[1]). If so, call it.
         * [1]: This idea is bound to find issues on mremaps. I don't know how we're going to deal
         * with this yet. */
        if (vma->vm_start > page_addr || vma->vm_end <= page_addr)
            continue;
        /* TODO: Ideally we'd go possibly down the tree and find the pte immediately (and do the
         * upfront checks for the page being mapped and the same page that we're looking for). But
         * the current interfaces aren't suited for this */
        st = info->walk_one(vma, page, page_addr, info->context);
        if (st)
            break;
    }

    spin_unlock(&anon_vma->lock);
    return st;
}

static inline void vm_obj_assert_interval_tree(size_t pgoff, struct vm_area_struct *vma)
{
    const off_t vmregion_end = vma->vm_offset + (vma_pages(vma) << PAGE_SHIFT);
    DCHECK(vma->vm_objhead.start <= pgoff && vma->vm_objhead.end >= pgoff);
    DCHECK(vma->vm_offset <= (off_t) (pgoff << PAGE_SHIFT) &&
           vmregion_end > (off_t) (pgoff << PAGE_SHIFT));
    DCHECK((vma->vm_offset >> PAGE_SHIFT) == (off_t) vma->vm_objhead.start &&
           vma->vm_objhead.end == (vma->vm_offset >> PAGE_SHIFT) + vma_pages(vma) - 1);
}

static int rmap_walk_file(struct rmap_walk_info *info, struct page *page)
{
    struct vm_object *obj = page->owner;
    spin_lock(&obj->mapping_lock);
    size_t offset = page->pageoff;
    struct vm_area_struct *vma;
    int st = 0;

    for_intervals_in_range(&obj->mappings, vma, struct vm_area_struct, vm_objhead, offset, offset)
    {
        vm_obj_assert_interval_tree(offset, vma);
        st = info->walk_one(vma, page, (vma->vm_start + (offset << PAGE_SHIFT) - vma->vm_offset),
                            info->context);
        if (st)
            break;
    }

    spin_unlock(&obj->mapping_lock);
    return st;
}

int rmap_walk(struct rmap_walk_info *info, struct page *page)
{
    if (page_flag_set(page, PAGE_FLAG_ANON))
        return rmap_walk_anon(info, page);
    return rmap_walk_file(info, page);
}

struct refs_info
{
    long references;
    unsigned int *vm_flags;
};

static int rmap_get_page_refs_one(struct vm_area_struct *vma, struct page *page, unsigned long addr,
                                  void *ctx)
{
    struct refs_info *info = ctx;
    info->references += mmu_get_clear_referenced(vma->vm_mm, (void *) addr, page);
    *info->vm_flags |= vma->vm_flags;
    return 0;
}

static long rmap_get_page_refs_anon(struct page *page, unsigned int *vm_flags)
{
    *vm_flags = 0;
    struct refs_info info = {};
    info.vm_flags = vm_flags;
    int st =
        rmap_walk_anon(&(struct rmap_walk_info){.walk_one = rmap_get_page_refs_one, &info}, page);
    if (st < 0)
        return st;
    return info.references;
}

long rmap_get_page_references(struct page *page, unsigned int *vm_flags)
{
    if (page_flag_set(page, PAGE_FLAG_ANON))
        return rmap_get_page_refs_anon(page, vm_flags);
    return vm_obj_get_page_references(page->owner, page, vm_flags);
}

static int rmap_try_to_unmap_one(struct vm_area_struct *vma, struct page *page, unsigned long addr,
                                 void *ctx)
{
    return try_to_unmap_one(page, vma, addr);
}

int rmap_try_to_unmap(struct page *page)
{
    struct rmap_walk_info info;
    info.walk_one = rmap_try_to_unmap_one;
    info.context = NULL;
    return rmap_walk(&info, page);
}
