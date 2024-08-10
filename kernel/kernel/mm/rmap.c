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
#include <onyx/page.h>
#include <onyx/rmap.h>

static struct slab_cache *anon_vma_cache;

void __init anon_vma_init(void)
{
    anon_vma_cache = kmem_cache_create("anon_vma", sizeof(struct anon_vma),
                                       _Alignof(struct anon_vma), KMEM_CACHE_PANIC, NULL);
}

struct anon_vma *anon_vma_alloc(void)
{
    struct anon_vma *anon = kmem_cache_alloc(anon_vma_cache, GFP_KERNEL);
    if (anon)
    {
        spinlock_init(&anon->lock);
        INIT_LIST_HEAD(&anon->vma_list);
    }

    return anon;
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
