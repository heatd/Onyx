/*
 * Copyright (c) 2023 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/dentry.h>
#include <onyx/mm/page_lru.h>
#include <onyx/mm/shmem.h>
#include <onyx/page.h>
#include <onyx/rmap.h>
#include <onyx/vm.h>
#include <onyx/vm_fault.h>

static int vm_anon_fault(struct vm_pf_context *ctx);
static int vm_anon_huge_pmd_fault(struct vm_pf_context *ctx);

const struct vm_operations anon_vmops = {
    .fault = vm_anon_fault,
    .fault_huge_pmd = vm_anon_huge_pmd_fault,
};

/* Don't access directly unless you know what you're doing. */
struct folio *__huge_zero_folio;
static struct folio *vm_get_huge_zero_folio(void)
{
    struct folio *folio;

again:
    if (likely(READ_ONCE(__huge_zero_folio)))
        return READ_ONCE(__huge_zero_folio);

    folio = folio_alloc(PMD_SHIFT - PTE_SHIFT, GFP_KERNEL);
    if (!folio)
        return NULL;
    if (cmpxchg(&__huge_zero_folio, (struct folio *) NULL, folio) != NULL)
    {
        /* Someone beat us to it, free it and retry */
        free_page(folio_to_page(folio));
        goto again;
    }
    return folio;
}

static int huge_anon_pmd_write(struct vm_pf_context *ctx)
{
    struct mm_address_space *mm = ctx->entry->vm_mm;
    struct spinlock *lock;
    struct folio *folio;
    pmd_t *pmd;
    u64 phys;
    int err;

    struct anon_vma *anon = anon_vma_prepare(ctx->entry);
    if (!anon)
        return -ENOMEM;

    /* Allocate a brand-new, zero-filled page */
    folio = folio_alloc(PMD_SHIFT - PTE_SHIFT, GFP_KERNEL);
    if (!folio)
        goto enomem;
    folio_set_anon(folio);
    inc_folio_stat(folio, NR_ANON);
    folio->owner = (struct vm_object *) anon;
    folio->pageoff = ctx->vpage;
    folio_add_lru(folio);
    folio_set_dirty(folio);

    pmd = ctx->pmd;
    lock = pmd_lockptr(mm, pmd);

    err = 0;
    spin_lock(lock);
    CHECK(pmd != NULL);
    if (pmd->pmd != ctx->oldpmd.pmd)
    {
        /* Ruh roh. Someone raced with us. Pretend everything worked. */
        goto err_unlock;
    }

    phys = (u64) folio_to_phys(folio);
    folio_add_mapcount(folio);
    /* TODO: set_pmd_over for ARM64 */
    set_pmd(pmd, pmd_mkpmd_huge(phys, calc_pgprot(phys, ctx->page_rwx)));
err_unlock:
    spin_unlock(lock);
    if (err == 0)
        mmu_invalidate_range(ctx->vpage & -PMD_SIZE, 1, mm);
    folio_put(folio);
    return err;
enomem:
    ctx->info->error_info = VM_SIGSEGV;
    return -ENOMEM;
}

static int vm_anon_huge_pmd_fault(struct vm_pf_context *ctx)
{
    struct mm_address_space *mm = ctx->entry->vm_mm;
    struct fault_info *info = ctx->info;
    struct spinlock *lock;
    struct folio *folio;
    pmd_t *pmd;
    u64 phys;
    int err;

    /* We don't deal with wp faults (do_wp_page should know to split the PMD properly). */
    if (pmd_present(ctx->oldpmd))
    {
        if (!pmd_huge(ctx->oldpmd))
            return -EAGAIN;
        /* except for the huge zero folio */
        if (__huge_zero_folio && pmd_addr(ctx->oldpmd) == (u64) (folio_to_phys(__huge_zero_folio)))
        {
            WARN_ON(!info->write);
            WARN_ON(pmd_write(ctx->oldpmd));
            return huge_anon_pmd_write(ctx);
        }
        return -EAGAIN;
    }

    if (!info->write)
    {
        folio = vm_get_huge_zero_folio();
        if (!folio)
            goto fallback;
        ctx->page_rwx &= ~VM_WRITE;
        ctx->page_rwx |= VM_PFNMAP;
    }
    else
    {
        struct anon_vma *anon = anon_vma_prepare(ctx->entry);
        if (!anon)
            return -ENOMEM;

        /* Allocate a brand-new, zero-filled page */
        folio = folio_alloc(PMD_SHIFT - PTE_SHIFT, GFP_KERNEL);
        if (!folio)
            goto enomem;
        folio_set_anon(folio);
        inc_folio_stat(folio, NR_ANON);
        folio->owner = (struct vm_object *) anon;
        folio->pageoff = ctx->vpage;
        folio_add_lru(folio);
        folio_set_dirty(folio);
    }

    pmd = ctx->pmd;
    lock = pmd_lockptr(mm, pmd);

    err = 0;
    spin_lock(lock);
    CHECK(pmd != NULL);
    if (pmd->pmd != ctx->oldpmd.pmd)
    {
        /* Ruh roh. Someone raced with us. Pretend everything worked. */
        goto err_unlock;
    }

    phys = (u64) folio_to_phys(folio);
    if (info->write)
        folio_add_mapcount(folio);
    /* Note: we use VM_PFNMAP to convince calc_pgprot to set SPECIAL */
    set_pmd(pmd, pmd_mkpmd_huge(phys, calc_pgprot(phys, ctx->page_rwx)));
    increment_vm_stat(mm, resident_set_size, PMD_SIZE);
err_unlock:
    spin_unlock(lock);
    if (info->write)
        folio_put(folio);
    return err;
enomem:
    info->error_info = VM_SIGSEGV;
    return -ENOMEM;
fallback:
    return -EAGAIN;
}

static int vm_anon_fault(struct vm_pf_context *ctx)
{
    struct vm_area_struct *vma = ctx->entry;
    struct fault_info *info = ctx->info;
    struct page *page = NULL;
    pte_t *ptep;
    struct spinlock *lock;

    /* pte_present is done in do_wp_page, not here. */
    CHECK(!pte_present(ctx->oldpte));
    /* Permission checks have already been handled before .fault() */
    if (!info->write)
    {
        /* Don't copy, just fault the zero page */
        page = vm_get_zero_page();
        /* Write protect the page and don't bother flushing the TLB */
        ctx->page_rwx &= ~VM_WRITE;
    }
    else
    {
        struct anon_vma *anon = anon_vma_prepare(ctx->entry);
        if (!anon)
            return -ENOMEM;

        /* Allocate a brand-new, zero-filled page */
        page = alloc_page(GFP_KERNEL);
        if (!page)
            goto enomem;
        page_set_anon(page);
        page->owner = (struct vm_object *) anon;
        page->pageoff = ctx->vpage;
        folio_add_lru(page_folio(page));
        page_set_dirty(page);
    }

    if (pgtable_prealloc(vma->vm_mm, ctx->vpage) < 0)
        goto enomem;

    ptep = ptep_get_locked(vma->vm_mm, ctx->vpage, &lock);
    if (ptep->pte != ctx->oldpte.pte)
        goto out;

    increment_vm_stat(vma->vm_mm, resident_set_size, PAGE_SIZE);
    page_add_mapcount(page);
    set_pte(ptep, pte_mkpte((u64) page_to_phys(page),
                            calc_pgprot((u64) page_to_phys(page), ctx->page_rwx)));

out:
    spin_unlock(lock);
    /* The mapcount holds the only reference we need for anon pages... */
    if (info->write)
        page_unref(page);
    return 0;
enomem:
    info->error_info = VM_SIGSEGV;
    return -ENOMEM;
}
