/*
 * Copyright (c) 2024 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/filemap.h>
#include <onyx/mm/page_lru.h>
#include <onyx/pgtable.h>
#include <onyx/process.h>
#include <onyx/rmap.h>
#include <onyx/swap.h>
#include <onyx/vm.h>
#include <onyx/vm_fault.h>

static p4d_t *__p4d_alloc(struct mm_address_space *mm)
{
    gfp_t gfp = GFP_KERNEL;
    struct page *page;

    /* Note that for kernel mappings we do ATOMIC allocations, for various reasons, including that
     * of vmalloc being called from atomic context. Such is life. */
    if (mm == &kernel_address_space)
        gfp = GFP_ATOMIC;
    page = alloc_page(gfp);
    if (!page)
        return NULL;
    return page_to_phys(page);
}

p4d_t *p4d_alloc(pgd_t *pgd, unsigned long addr, struct mm_address_space *mm)
{
    pgprotval_t perms = addr < VM_USER_ADDR_LIMIT ? USER_PGTBL : KERNEL_PGTBL;
    p4d_t *p4d = __p4d_alloc(mm);
    if (!p4d)
        return NULL;
    spin_lock(&mm->page_table_lock);
    /* Recheck under the lock - someone might've allocated the table while we were not looking. */
    if (!pgd_none(*pgd))
    {
        free_page(phys_to_page((unsigned long) p4d));
        p4d = p4d_offset(pgd, addr);
        spin_unlock(&mm->page_table_lock);
        return p4d;
    }

    set_pgd(pgd, pgd_mkpgd((unsigned long) p4d, __pgprot(perms)));
    increment_vm_stat(mm, page_tables_size, PAGE_SIZE);
    spin_unlock(&mm->page_table_lock);
    return (p4d_t *) __tovirt(p4d) + p4d_index(addr);
}

p4d_t *p4d_get_or_alloc(pgd_t *pgd, unsigned long addr, struct mm_address_space *mm)
{
    DCHECK(!spin_lock_held(&mm->page_table_lock));
    if (likely(!pgd_none(*pgd)))
        return p4d_offset(pgd, addr);
    return p4d_alloc(pgd, addr, mm);
}

static pud_t *__pud_alloc(struct mm_address_space *mm)
{
    gfp_t gfp = GFP_KERNEL;
    struct page *page;

    /* Note that for kernel mappings we do ATOMIC allocations, for various reasons, including that
     * of vmalloc being called from atomic context. Such is life. */
    if (mm == &kernel_address_space)
        gfp = GFP_ATOMIC;
    page = alloc_page(gfp);
    if (!page)
        return NULL;
    return page_to_phys(page);
}

pud_t *pud_alloc(p4d_t *p4d, unsigned long addr, struct mm_address_space *mm)
{
    pgprotval_t perms = addr < VM_USER_ADDR_LIMIT ? USER_PGTBL : KERNEL_PGTBL;
    pud_t *pud = __pud_alloc(mm);
    if (!pud)
        return NULL;
    spin_lock(&mm->page_table_lock);
    /* Recheck under the lock - someone might've allocated the table while we were not looking. */
    if (!p4d_none(*p4d))
    {
        free_page(phys_to_page((unsigned long) pud));
        pud = pud_offset(p4d, addr);
        spin_unlock(&mm->page_table_lock);
        return pud;
    }

    set_p4d(p4d, p4d_mkp4d((unsigned long) pud, __pgprot(perms)));
    increment_vm_stat(mm, page_tables_size, PAGE_SIZE);
    spin_unlock(&mm->page_table_lock);
    return (pud_t *) __tovirt(pud) + pud_index(addr);
}

pud_t *pud_get_or_alloc(p4d_t *p4d, unsigned long addr, struct mm_address_space *mm)
{
    DCHECK(!spin_lock_held(&mm->page_table_lock));
    if (likely(!p4d_none(*p4d)))
        return pud_offset(p4d, addr);
    return pud_alloc(p4d, addr, mm);
}

static pmd_t *__pmd_alloc(struct mm_address_space *mm)
{
    gfp_t gfp = GFP_KERNEL;
    struct page *page;

    /* Note that for kernel mappings we do ATOMIC allocations, for various reasons, including that
     * of vmalloc being called from atomic context. Such is life. */
    if (mm == &kernel_address_space)
        gfp = GFP_ATOMIC;
    page = alloc_page(gfp);
    if (!page)
        return NULL;
    return page_to_phys(page);
}

pmd_t *pmd_alloc(pud_t *pud, unsigned long addr, struct mm_address_space *mm)
{
    pgprotval_t perms = addr < VM_USER_ADDR_LIMIT ? USER_PGTBL : KERNEL_PGTBL;
    pmd_t *pmd = __pmd_alloc(mm);
    if (!pmd)
        return NULL;

    spin_lock(&mm->page_table_lock);
    /* Recheck under the lock - someone might've allocated the table while we were not looking. */
    if (!pud_none(*pud))
    {
        free_page(phys_to_page((unsigned long) pmd));
        pmd = pmd_offset(pud, addr);
        spin_unlock(&mm->page_table_lock);
        return pmd;
    }

    set_pud(pud, pud_mkpud((unsigned long) pmd, __pgprot(perms)));
    increment_vm_stat(mm, page_tables_size, PAGE_SIZE);
    spin_unlock(&mm->page_table_lock);
    return (pmd_t *) __tovirt(pmd) + pmd_index(addr);
}

pmd_t *pmd_get_or_alloc(pud_t *pud, unsigned long addr, struct mm_address_space *mm)
{
    DCHECK(!spin_lock_held(&mm->page_table_lock));
    if (likely(!pud_none(*pud)))
        return pmd_offset(pud, addr);
    return pmd_alloc(pud, addr, mm);
}

static pte_t *__pte_alloc(struct mm_address_space *mm)
{
    gfp_t gfp = GFP_KERNEL;
    struct page *page;

    /* Note that for kernel mappings we do ATOMIC allocations, for various reasons, including that
     * of vmalloc being called from atomic context. Such is life. */
    if (mm == &kernel_address_space)
        gfp = GFP_ATOMIC;
    page = alloc_page(gfp);
    if (!page)
        return NULL;
    return page_to_phys(page);
}

pte_t *pte_alloc(pmd_t *pmd, unsigned long addr, struct mm_address_space *mm)
{
    pgprotval_t perms = addr < VM_USER_ADDR_LIMIT ? USER_PGTBL : KERNEL_PGTBL;
    pte_t *pte = __pte_alloc(mm);
    if (!pte)
        return NULL;

    spin_lock(&mm->page_table_lock);
    /* Recheck under the lock - someone might've allocated the table while we were not looking. */
    if (!pmd_none(*pmd))
    {
        free_page(phys_to_page((unsigned long) pte));
        pte = pte_offset(pmd, addr);
        spin_unlock(&mm->page_table_lock);
        return pte;
    }

    set_pmd(pmd, pmd_mkpmd((unsigned long) pte, __pgprot(perms)));
    increment_vm_stat(mm, page_tables_size, PAGE_SIZE);
    inc_page_stat(phys_to_page((unsigned long) pte), NR_PTES);
    spin_unlock(&mm->page_table_lock);
    return (pte_t *) __tovirt(pte) + pte_index(addr);
}

pte_t *pte_get_or_alloc(pmd_t *pmd, unsigned long addr, struct mm_address_space *mm)
{
    DCHECK(!spin_lock_held(&mm->page_table_lock));
    if (likely(!pmd_none(*pmd)))
        return pte_offset(pmd, addr);
    return pte_alloc(pmd, addr, mm);
}

/**
 * @brief Directly maps a page into the paging tables.
 *
 * @param as The target address space.
 * @param virt The virtual address.
 * @param phys The physical address of the page.
 * @param prot Desired protection flags.
 * @param vma VMA for this mapping (optional)
 * @return NULL if out of memory, else virt.
 */
void *vm_map_page(struct mm_address_space *as, uint64_t virt, uint64_t phys, uint64_t prot,
                  struct vm_area_struct *vma)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    bool ispfnmap = vma_is_pfnmap(vma);
    bool special_mapping = phys == (u64) page_to_phys(vm_get_zero_page());

    pgd = pgd_offset(as, virt);

    p4d = p4d_get_or_alloc(pgd, virt, as);
    if (unlikely(!p4d))
        return NULL;

    pud = pud_get_or_alloc(p4d, virt, as);
    if (unlikely(!pud))
        return NULL;

    pmd = pmd_get_or_alloc(pud, virt, as);
    if (unlikely(!pmd))
        return NULL;

    pte = pte_get_or_alloc(pmd, virt, as);
    if (unlikely(!pte))
        return NULL;

    pte_lock(pte, as);
    pte_t oldpte = *pte;
    pgprot_t pgprot = calc_pgprot(phys, prot);
    set_pte(pte, pte_mkpte(phys, pgprot));

    if (!pte_present(oldpte))
        increment_vm_stat(as, resident_set_size, PAGE_SIZE);

    if (likely(!ispfnmap))
    {
        if (prot & VM_DONT_MAP_OVER)
            WARN_ON(pte_addr(oldpte) != phys);

        struct page *newp = phys_to_page(phys);
        if (likely(!special_mapping))
            page_add_mapcount(newp);

        if (unlikely(pte_present(oldpte) && !pte_special(oldpte)))
        {
            /* If old was a thing, decrement the mapcount */
            struct page *oldp = phys_to_page(pte_addr(oldpte));
            page_sub_mapcount(oldp);
        }
    }

    pte_unlock(pte, as);
    return (void *) virt;
}

unsigned int mmu_get_clear_referenced(struct mm_address_space *mm, void *addr, struct page *page)
{
    int ret = 0;
    pte_t *ptep;
    struct spinlock *lock;

    ptep = ptep_get_locked(mm, (unsigned long) addr, &lock);
    if (!ptep)
        return ret;

    pte_t old = *ptep;
    pte_t new_pte;
    do
    {
        if (!pte_present(old) || !pte_accessed(old))
            goto out;
        if (pte_addr(old) != (unsigned long) page_to_phys(page))
            goto out;
        new_pte = pte_mkyoung(*ptep);
    } while (!pte_cmpxchg(ptep, &old, new_pte));

    ret = 1;
    /* Architectural note: We don't need to flush the TLB. Flushing the TLB is required by x86 if we
     * want the A bit to be set again, but we can just wait for an unrelated TLB flush (e.g context
     * switch) to do the job for us. A TLB shootdown is too much overhead for this purpose. */
out:
    spin_unlock(lock);
    return ret;
}

static unsigned long p4d_to_mapping_info(p4d_t p4d)
{
    unsigned long ret = p4d_addr(p4d) | PAGE_PRESENT | PAGE_HUGE;
    if (p4d_write(p4d))
        ret |= PAGE_WRITABLE;
    if (p4d_exec(p4d))
        ret |= PAGE_EXECUTABLE;
    if (p4d_global(p4d))
        ret |= PAGE_GLOBAL;
    if (p4d_dirty(p4d))
        ret |= PAGE_DIRTY;
    if (p4d_accessed(p4d))
        ret |= PAGE_ACCESSED;
    if (p4d_user(p4d))
        ret |= PAGE_USER;
    return ret;
}

static unsigned long pud_to_mapping_info(pud_t pud)
{
    unsigned long ret = pud_addr(pud) | PAGE_PRESENT | PAGE_HUGE;
    if (pud_write(pud))
        ret |= PAGE_WRITABLE;
    if (pud_exec(pud))
        ret |= PAGE_EXECUTABLE;
    if (pud_global(pud))
        ret |= PAGE_GLOBAL;
    if (pud_dirty(pud))
        ret |= PAGE_DIRTY;
    if (pud_accessed(pud))
        ret |= PAGE_ACCESSED;
    if (pud_user(pud))
        ret |= PAGE_USER;
    return ret;
}

static unsigned long pmd_to_mapping_info(pmd_t pmd)
{
    unsigned long ret = pmd_addr(pmd) | PAGE_PRESENT | PAGE_HUGE;
    if (pmd_write(pmd))
        ret |= PAGE_WRITABLE;
    if (pmd_exec(pmd))
        ret |= PAGE_EXECUTABLE;
    if (pmd_global(pmd))
        ret |= PAGE_GLOBAL;
    if (pmd_dirty(pmd))
        ret |= PAGE_DIRTY;
    if (pmd_accessed(pmd))
        ret |= PAGE_ACCESSED;
    if (pmd_user(pmd))
        ret |= PAGE_USER;
    return ret;
}

static unsigned long pte_to_mapping_info(pte_t pte)
{
    unsigned long ret = pte_addr(pte) | PAGE_PRESENT;
    if (pte_write(pte))
        ret |= PAGE_WRITABLE;
    if (pte_exec(pte))
        ret |= PAGE_EXECUTABLE;
    if (pte_global(pte))
        ret |= PAGE_GLOBAL;
    if (pte_dirty(pte))
        ret |= PAGE_DIRTY;
    if (pte_accessed(pte))
        ret |= PAGE_ACCESSED;
    if (pte_user(pte))
        ret |= PAGE_USER;
    return ret;
}

unsigned long __get_mapping_info(void *addr, struct mm_address_space *mm)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long virt = (unsigned long) addr;
    pgd = pgd_offset(mm, virt);
    if (!pgd_present(*pgd))
        return PAGE_NOT_PRESENT;

    p4d = p4d_offset(pgd, virt);
    if (!p4d_present(*p4d))
        return PAGE_NOT_PRESENT;
    if (p4d_huge(*p4d))
        return p4d_to_mapping_info(*p4d);

    pud = pud_offset(p4d, virt);
    if (!pud_present(*pud))
        return PAGE_NOT_PRESENT;
    if (pud_huge(*pud))
        return pud_to_mapping_info(*pud);

    pmd = pmd_offset(pud, virt);
    if (!pmd_present(*pmd))
        return PAGE_NOT_PRESENT;
    if (pmd_huge(*pmd))
        return pmd_to_mapping_info(*pmd);

    pte = pte_offset(pmd, virt);
    if (!pte_present(*pte))
        return PAGE_NOT_PRESENT;

    return pte_to_mapping_info(*pte);
}

struct tlbi_batch
{
    struct list_head list_node;
    unsigned int used_pending_pages;
    struct page *pending_pages[];
};

#define MAX_PENDING_PAGEN ((PAGE_SIZE - (offsetof(struct tlbi_batch, pending_pages))) / 8)

struct unmap_info
{
    struct tlbi_tracker *tlbi;
    struct mm_address_space *mm;
    struct vm_area_struct *vma;
    int kernel : 1, full : 1, freepgtables : 1;
};

enum unmap_result
{
    UNMAP_OK = 0,
    /* We *know* this page table is clear. Note that a page table can be clear even if this isn't
     * set.
     */
    UNMAP_FREE_PGTABLE = 1,
    /* We *know* this page is not clear. Don't bother checking. */
    UNMAP_DONT_FREE = (1 << 1)
};

void tlbi_end_batch(struct tlbi_tracker *tlbi)
{
    struct tlbi_batch *batch, *next;
    struct page *page;

    vm_invalidate_range(tlbi->start, (tlbi->end - tlbi->start) >> PAGE_SHIFT);
    list_for_each_entry_safe (batch, next, &tlbi->batches, list_node)
    {
        /* TODO: Efficient way to unref many pages at a time. */
        for (unsigned int i = 0; i < batch->used_pending_pages; i++)
            page_unref(batch->pending_pages[i]);
        list_remove(&batch->list_node);
        page = phys_to_page(VIRT_TO_PHYS(batch));
        CHECK((unsigned long) page > 0xf0000);
        free_page(page);
    }

    tlbi->active = false;
}

static bool tlbi_add_defer_free(struct tlbi_tracker *tlbi, struct page *page)
{
    struct tlbi_batch *batch;
    struct page *batchpage;

    batch = list_is_empty(&tlbi->batches)
                ? NULL
                : list_last_entry(&tlbi->batches, struct tlbi_batch, list_node);
    if (!batch || batch->used_pending_pages == MAX_PENDING_PAGEN)
    {
        /* Allocate a new batch and append it */
        batchpage = alloc_page(GFP_ATOMIC | __GFP_NOWARN);
        if (!batchpage)
            return false;
        batch = PAGE_TO_VIRT(batchpage);
        batch->used_pending_pages = 0;
        list_add_tail(&batch->list_node, &tlbi->batches);
    }

    batch->pending_pages[batch->used_pending_pages++] = page;
    return true;
}

static void tlbi_remove_page(struct tlbi_tracker *tlbi, unsigned long addr, struct page *page)
{
retry:
    if (!tlbi->active)
    {
        tlbi->start = addr;
        tlbi->end = addr + PAGE_SIZE;
        tlbi->active = true;
        goto out;
    }

    /* TODO: Measure this heuristic. We need a solid, realistic benchmark that allows us to measure
     * the cost of flushing too much TLB */
    /* If the new page is too far away (say, a PMD of distance), flush this batch and start anew. If
     * we have a page to queue, and the defer queue is empty, flush the batch and start anew. */
    if (/*(long) (tlbi->start - addr) >= (long) PMD_SIZE ||
       (long) (addr - tlbi->end) >= (long) PMD_SIZE ||*/
        (page))
    {
        // goto retry;
    }

    if (addr < tlbi->start)
        tlbi->start = addr;
    else if (addr >= tlbi->end)
        tlbi->end = addr + PAGE_SIZE;
out:
    if (page)
    {
        if (!tlbi_add_defer_free(tlbi, page))
        {
            tlbi_end_batch(tlbi);
            /* TODO: This is iffy. */
            if (!tlbi_add_defer_free(tlbi, page))
                panic("Crap");
            goto retry;
        }
    }
}

static bool tlbi_defer_page_queue_full(struct tlbi_tracker *tlbi)
{
    /* XXX: Maybe remove */
    return true;
}

static bool tlbi_covers(struct tlbi_tracker *tlbi, unsigned long start, unsigned long end)
{
    return start <= tlbi->end && tlbi->start <= end;
}

bool tlbi_active(struct tlbi_tracker *tlbi)
{
    return tlbi->active;
}

/* x86 implementation of PTE removal. Intel SDM says (4.10.4.2 Recommended Invalidation) we must
 * shootdown all mappings with translations under this paging structure. However, if no paging
 * structure existed, we must call invlpg at least once. */
static void x86_tlbi_remove_entry(struct mm_address_space *mm, struct tlbi_tracker *tlbi,
                                  unsigned long pgtbl_phys, unsigned long addr, unsigned long end,
                                  unsigned long entry_size)
{
    struct page *page = phys_to_page(pgtbl_phys);

    /* We'll pick the last address in the page table, because we're likely to go forward ("upwards")
     * when doing TLB operations. But only if we don't yet cover this PMD in the existing
     * invalidation. */
    if (!tlbi_covers(tlbi, addr & -entry_size, end) || tlbi_defer_page_queue_full(tlbi))
        tlbi_remove_page(tlbi, end - PAGE_SIZE, page);
    else
        tlbi_add_defer_free(tlbi, page);
    decrement_vm_stat(mm, page_tables_size, PAGE_SIZE);
}

static void tlbi_remove_pte(struct mm_address_space *mm, struct tlbi_tracker *tlbi, pte_t *pte,
                            unsigned long addr)
{
    x86_tlbi_remove_entry(mm, tlbi, (unsigned long) pte - PHYS_BASE, addr, pmd_addr_end(addr),
                          PMD_SIZE);
}

static void tlbi_remove_pmd(struct mm_address_space *mm, struct tlbi_tracker *tlbi, pmd_t *pmd,
                            unsigned long addr)
{
    x86_tlbi_remove_entry(mm, tlbi, (unsigned long) pmd - PHYS_BASE, addr, pud_addr_end(addr),
                          PUD_SIZE);
}

static void tlbi_remove_pud(struct mm_address_space *mm, struct tlbi_tracker *tlbi, pud_t *pud,
                            unsigned long addr)
{
    x86_tlbi_remove_entry(mm, tlbi, (unsigned long) pud - PHYS_BASE, addr, p4d_addr_end(addr),
                          P4D_SIZE);
}

static void tlbi_remove_p4d(struct mm_address_space *mm, struct tlbi_tracker *tlbi, p4d_t *p4d,
                            unsigned long addr)
{
    x86_tlbi_remove_entry(mm, tlbi, (unsigned long) p4d - PHYS_BASE, addr, pgd_addr_end(addr),
                          PGD_SIZE);
}

static void tlbi_update_page_prots(struct tlbi_tracker *tlbi, unsigned long addr, pte_t old,
                                   pte_t new)
{
    /* TODO: We can take the spurious faults on permission upgrade, *if* the PFN is the same (if
     * not, we risk exposing stale data to userspace). */
    tlbi_remove_page(tlbi, addr, NULL);
}

static void tlbi_update_page_prots_huge_pmd(struct tlbi_tracker *tlbi, unsigned long addr,
                                            pmd_t old, pmd_t new)
{
    /* TODO: We can take the spurious faults on permission upgrade, *if* the PFN is the same (if
     * not, we risk exposing stale data to userspace). */
    tlbi_remove_page(tlbi, addr, NULL);
}

static enum unmap_result pte_unmap_range(struct unmap_info *uinfo, pte_t *pte, unsigned long start,
                                         unsigned long end)
{
    unsigned long next_start;
    int clear = 0;

    pte_lock(pte, uinfo->mm);
    for (; start < end; pte++, start = next_start, clear++)
    {
        next_start = min(pte_addr_end(start), end);
        pte_t old = *pte;
        struct page *page = NULL;
        if (pte_none(old))
            continue;

        if (!pte_present(old))
        {
            swp_entry_t entry = pte_to_swp_entry(old);
            swap_put(entry);
        }

        if (!uinfo->kernel && !pte_special(old) && (pte_present(old) || pte_protnone(old)))
        {
            page = phys_to_page(pte_addr(old));
            /* Ref the page, so it doesn't go away before the tlbi */
            page_ref(page);
            page_sub_mapcount(page);
        }

        if (pte_present(old) || pte_protnone(old))
            decrement_vm_stat(uinfo->mm, resident_set_size, PAGE_SIZE);
        set_pte(pte, __pte(0));
        tlbi_remove_page(uinfo->tlbi, start, page);
    }

    pte_unlock(pte - 1, uinfo->mm);

    /* If we *know* the page table is clear, tell it to the caller so we skip expensive checks */
    if (clear == PTRS_PER_PTE)
        return UNMAP_FREE_PGTABLE;

    return UNMAP_OK;
}

static int pmd_free_pte(struct unmap_info *uinfo, pmd_t *pmd, unsigned long addr, int flags)
{
    struct page *pte_page;
    pte_t *pte = (pte_t *) __tovirt(pmd_addr(*pmd));
    if (!(flags & UNMAP_FREE_PGTABLE))
    {
        /* Check if the page table is clear */
        for (int i = 0; i < PTRS_PER_PTE; i++)
        {
            if (!pte_none(*(pte + i)))
                return 0;
        }
    }

    set_pmd(pmd, __pmd(0));
    pte_page = phys_to_page(((unsigned long) pte) - PHYS_BASE);
    dec_page_stat(pte_page, NR_PTES);
    tlbi_remove_pte(uinfo->mm, uinfo->tlbi, pte, addr);
    return 1;
}

static int pud_free_pmd(struct unmap_info *uinfo, pud_t *pud, unsigned long addr, int flags)
{
    pmd_t *pmd = (pmd_t *) __tovirt(pud_addr(*pud));
    if (!(flags & UNMAP_FREE_PGTABLE))
    {
        /* Check if the page table is clear */
        for (int i = 0; i < PTRS_PER_PMD; i++)
        {
            if (!pmd_none(*(pmd + i)))
                return 0;
        }
    }

    set_pud(pud, __pud(0));
    tlbi_remove_pmd(uinfo->mm, uinfo->tlbi, pmd, addr);
    return 1;
}

static int p4d_free_pud(struct unmap_info *uinfo, p4d_t *p4d, unsigned long addr, int flags)
{
    pud_t *pud = (pud_t *) __tovirt(p4d_addr(*p4d));
    if (!(flags & UNMAP_FREE_PGTABLE))
    {
        /* Check if the page table is clear */
        for (int i = 0; i < PTRS_PER_PUD; i++)
        {
            if (!pud_none(*(pud + i)))
                return 0;
        }
    }

    set_p4d(p4d, __p4d(0));
    tlbi_remove_pud(uinfo->mm, uinfo->tlbi, pud, addr);
    return 1;
}

static int pgd_free_p4d(struct unmap_info *uinfo, pgd_t *pgd, unsigned long addr, int flags)
{
    p4d_t *p4d = (p4d_t *) __tovirt(pgd_addr(*pgd));
    if (!(flags & UNMAP_FREE_PGTABLE))
    {
        /* Check if the page table is clear */
        for (int i = 0; i < PTRS_PER_P4D; i++)
        {
            if (!p4d_none(*(p4d + i)))
                return 0;
        }
    }

    set_pgd(pgd, __pgd(0));
    tlbi_remove_p4d(uinfo->mm, uinfo->tlbi, p4d, addr);
    return 1;
}

static struct spinlock *pmd_lock_huge(struct mm_address_space *mm, pmd_t *pmd)
{
    struct spinlock *lock = pmd_lockptr(mm, pmd);

    /* Because of possible races (particularly when THP gets introduced), we must recheck if the pmd
     * is a huge page under the lock. If not, return NULL */
    spin_lock(lock);
    if (likely(pmd_huge(*pmd)))
        return lock;
    spin_unlock(lock);
    return NULL;
}

static bool pmd_unmap_huge(struct unmap_info *uinfo, pmd_t *pmd, unsigned long start,
                           unsigned long end)
{
    struct folio *folio = NULL;
    pmd_t old = *pmd;
    struct spinlock *lock;

    /* Hugepage splitting not yet supported */
    CHECK((end & (PMD_SIZE - 1)) == 0);

    lock = pmd_lock_huge(uinfo->mm, pmd);
    if (!lock)
        return false;

    if (!uinfo->kernel && (pmd_present(old) || pmd_protnone(old)))
    {
        folio = phys_to_folio(pmd_addr(old));
        /* Ref the page, so it doesn't go away before the tlbi */
        folio_get(folio);
        folio_sub_mapcount(folio);
    }

    if (pmd_present(old) || pmd_protnone(old))
        decrement_vm_stat(uinfo->mm, resident_set_size, PMD_SIZE);
    set_pmd(pmd, __pmd(0));

    spin_unlock(lock);
    tlbi_remove_page(uinfo->tlbi, start, folio_to_page(folio));
    return true;
}

static enum unmap_result pmd_unmap_range(struct unmap_info *uinfo, pmd_t *pmd, unsigned long start,
                                         unsigned long end)
{
    unsigned long next_start;
    int clear = 0;
    enum unmap_result ret = UNMAP_OK;
    for (; start < end; pmd++, start = next_start)
    {
        next_start = min(pmd_addr_end(start), end);
        if (pmd_none(*pmd))
        {
            clear++;
            continue;
        }

        if (pmd_huge(*pmd))
        {
            pmd_unmap_huge(uinfo, pmd, start, next_start);
            clear++;
            continue;
        }

        enum unmap_result res = pte_unmap_range(uinfo, pte_offset(pmd, start), start, next_start);
        if (uinfo->freepgtables)
        {
            if (pmd_free_pte(uinfo, pmd, start & -PMD_SIZE, res))
                clear++;
            else
                ret |= UNMAP_DONT_FREE;
        }
    }

    if (clear == PTRS_PER_PMD)
        return UNMAP_FREE_PGTABLE;
    return ret;
}

static enum unmap_result pud_unmap_range(struct unmap_info *uinfo, pud_t *pud, unsigned long start,
                                         unsigned long end)
{
    unsigned long next_start;
    int clear = 0;
    enum unmap_result ret = UNMAP_OK;
    for (; start < end; pud++, start = next_start)
    {
        next_start = min(pud_addr_end(start), end);
        if (pud_none(*pud))
        {
            clear++;
            continue;
        }
        /* TODO: Huge page unmapping and splitting not supported yet... */
        DCHECK(!pud_huge(*pud));
        enum unmap_result res = pmd_unmap_range(uinfo, pmd_offset(pud, start), start, next_start);
        if (!pmd_folded() && uinfo->freepgtables && !(res & UNMAP_DONT_FREE))
        {
            if (pud_free_pmd(uinfo, pud, start & -PUD_SIZE, res))
                clear++;
            else
                ret |= UNMAP_DONT_FREE;
        }
    }

    if (clear == PTRS_PER_PUD)
        return UNMAP_FREE_PGTABLE;
    return ret;
}

static enum unmap_result p4d_unmap_range(struct unmap_info *uinfo, p4d_t *p4d, unsigned long start,
                                         unsigned long end)
{
    unsigned long next_start;
    int clear = 0;
    enum unmap_result ret = UNMAP_OK;
    for (; start < end; p4d++, start = next_start)
    {
        next_start = min(p4d_addr_end(start), end);
        if (p4d_none(*p4d))
        {
            clear++;
            continue;
        }
        /* TODO: Huge page unmapping and splitting not supported yet... */
        DCHECK(!p4d_huge(*p4d));
        enum unmap_result res = pud_unmap_range(uinfo, pud_offset(p4d, start), start, next_start);
        if (!pud_folded() && uinfo->freepgtables && !(res & UNMAP_DONT_FREE))
        {
            if (p4d_free_pud(uinfo, p4d, start & -P4D_SIZE, res))
                clear++;
            else
                ret |= UNMAP_DONT_FREE;
        }
    }

    if (clear == PTRS_PER_P4D)
        return UNMAP_FREE_PGTABLE;
    return ret;
}

static void pgd_unmap_range(struct unmap_info *uinfo, pgd_t *pgd, unsigned long start,
                            unsigned long end)
{
    unsigned long next_start;
    for (; start < end; pgd++, start = next_start)
    {
        next_start = min(pgd_addr_end(start), end);
        if (pgd_none(*pgd))
            continue;
        enum unmap_result res = p4d_unmap_range(uinfo, p4d_offset(pgd, start), start, next_start);
        if (!p4d_folded() && uinfo->freepgtables && !(res & UNMAP_DONT_FREE))
            pgd_free_p4d(uinfo, pgd, start & -PGD_SIZE, res);
    }
}

int vma_unmap(struct mm_address_space *mm, void *addr, size_t pages, struct vm_area_struct *vma,
              struct tlbi_tracker *tlbi)
{
    unsigned long virt = (unsigned long) addr;
    unsigned long end = virt + (pages << PAGE_SHIFT);
    struct unmap_info unmap_info;
    unmap_info.vma = vma;
    unmap_info.mm = mm;
    unmap_info.kernel = mm == &kernel_address_space;
    unmap_info.full = 0;
    unmap_info.freepgtables = 1;
    unmap_info.tlbi = tlbi;

    pgd_unmap_range(&unmap_info, pgd_offset(mm, virt), virt, end);
    /* Caller is responsible for calling tlbi_end_batch */
    return 0;
}

int vm_mmu_unmap(struct mm_address_space *mm, void *addr, size_t pages, struct vm_area_struct *vma)
{
    unsigned long virt = (unsigned long) addr;
    unsigned long end = virt + (pages << PAGE_SHIFT);
    struct unmap_info unmap_info;
    struct tlbi_tracker tlbi;
    unmap_info.vma = vma;
    unmap_info.mm = mm;
    unmap_info.kernel = mm == &kernel_address_space;
    unmap_info.full = 0;
    unmap_info.freepgtables = 1;
    unmap_info.tlbi = &tlbi;
    tlbi_tracker_init(&tlbi);

    pgd_unmap_range(&unmap_info, pgd_offset(mm, virt), virt, end);

    if (tlbi_active(&tlbi))
        tlbi_end_batch(&tlbi);
    return 0;
}

int zap_page_range(unsigned long start, unsigned long end, struct vm_area_struct *vma)
{
    struct mm_address_space *mm = vma->vm_mm;
    struct unmap_info unmap_info;
    struct tlbi_tracker tlbi;
    unmap_info.vma = vma;
    unmap_info.mm = mm;
    unmap_info.kernel = 0;
    unmap_info.full = 0;
    unmap_info.freepgtables = 0;
    unmap_info.tlbi = &tlbi;
    tlbi_tracker_init(&tlbi);

    pgd_unmap_range(&unmap_info, pgd_offset(mm, start), start, end);

    if (tlbi_active(&tlbi))
        tlbi_end_batch(&tlbi);
    return 0;
}

bool paging_write_protect(void *addr, struct mm_address_space *mm)
{
    struct spinlock *lock;
    pte_t *pte;

    pte = ptep_get_locked(mm, (unsigned long) addr, &lock);
    if (pte)
    {
        set_pte(pte, pte_wrprotect(*pte));
        spin_unlock(lock);
    }

    return pte != NULL;
}

static void pte_change_prot(pte_t *ptep, int vmflags)
{
    /* Note: Preserve the A and D bits */
    pte_t pte = *ptep;
    pte_t newpte = pte_mkpte(pte_addr(pte), calc_pgprot(pte_addr(pte), vmflags));
    if (pte_accessed(pte))
        pte_val(newpte) |= _PAGE_ACCESSED;
    if (pte_dirty(pte))
        pte_val(newpte) |= _PAGE_DIRTY;
    set_pte(ptep, newpte);
}

/* TODO: This is on the deprecated chopping block... */
bool __paging_change_perms(struct mm_address_space *mm, void *addr, int prot)
{
    struct spinlock *lock;
    pte_t *pte;

    pte = ptep_get_locked(mm, (unsigned long) addr, &lock);
    if (pte)
    {
        pte_change_prot(pte, prot);
        spin_unlock(lock);
    }

    return pte != NULL;
}

static void pte_protect_range(struct tlbi_tracker *tlbi, pte_t *pte, unsigned long start,
                              unsigned long end, int new_prots)
{
    unsigned long next_start;

    pte_lock(pte, get_current_address_space());
    for (; start < end; pte++, start = next_start)
    {
        next_start = min(pte_addr_end(start), end);
        pte_t old = *pte;
        if (pte_none(old))
            continue;

        pte_change_prot(pte, new_prots);
        tlbi_update_page_prots(tlbi, start, old, *pte);
    }

    pte_unlock(pte - 1, get_current_address_space());
}

static bool pmd_protect_huge(struct tlbi_tracker *tlbi, pmd_t *pmd, unsigned long start,
                             unsigned long end, int new_prots)
{
    pmd_t old, newpmd;
    struct spinlock *lock;
    /* Hugepage splitting not yet supported */
    CHECK((end & (PMD_SIZE - 1)) == 0);

    lock = pmd_lock_huge(get_current_address_space(), pmd);
    if (!lock)
        return false;

    /* Note: Preserve the A and D bits */
    old = *pmd;
    newpmd = pmd_mkpmd_huge(pmd_addr(old), calc_pgprot(pmd_addr(old), new_prots));
    if (pmd_accessed(old))
        pmd_val(newpmd) |= _PAGE_ACCESSED;
    if (pmd_dirty(old))
        pmd_val(old) |= _PAGE_DIRTY;
    set_pmd(pmd, newpmd);

    spin_unlock(lock);

    tlbi_update_page_prots_huge_pmd(tlbi, start, old, newpmd);
    return true;
}

static void pmd_protect_range(struct tlbi_tracker *tlbi, pmd_t *pmd, unsigned long start,
                              unsigned long end, int new_prots)
{
    unsigned long next_start;
    for (; start < end; pmd++, start = next_start)
    {
        next_start = min(pmd_addr_end(start), end);
        if (pmd_none(*pmd))
            continue;

        if (pmd_huge(*pmd))
        {
            /* Note: no one can fault this in because we hold the write lock. So, _if_ we go down
             * this, and we don't see a huge pmd with the lock held, then it means we don't need to
             * recheck - it will be pmd_none() */
            pmd_protect_huge(tlbi, pmd, start, next_start, new_prots);
            continue;
        }

        pte_protect_range(tlbi, pte_offset(pmd, start), start, next_start, new_prots);
    }
}

static void pud_protect_range(struct tlbi_tracker *tlbi, pud_t *pud, unsigned long start,
                              unsigned long end, int new_prots)
{
    unsigned long next_start;
    for (; start < end; pud++, start = next_start)
    {
        next_start = min(pud_addr_end(start), end);
        if (pud_none(*pud))
            continue;
        /* TODO: Huge page splitting not supported yet... */
        DCHECK(!pud_huge(*pud));
        pmd_protect_range(tlbi, pmd_offset(pud, start), start, next_start, new_prots);
    }
}

static void p4d_protect_range(struct tlbi_tracker *tlbi, p4d_t *p4d, unsigned long start,
                              unsigned long end, int new_prots)
{
    unsigned long next_start;
    for (; start < end; p4d++, start = next_start)
    {
        next_start = min(p4d_addr_end(start), end);
        if (p4d_none(*p4d))
            continue;

        /* TODO: Huge page splitting not supported yet... */
        DCHECK(!p4d_huge(*p4d));
        pud_protect_range(tlbi, pud_offset(p4d, start), start, next_start, new_prots);
    }
}

static void pgd_protect_range(struct tlbi_tracker *tlbi, pgd_t *pgd, unsigned long start,
                              unsigned long end, int new_prots)
{
    unsigned long next_start;
    for (; start < end; pgd++, start = next_start)
    {
        next_start = min(pgd_addr_end(start), end);
        if (pgd_none(*pgd))
            continue;
        p4d_protect_range(tlbi, p4d_offset(pgd, start), start, next_start, new_prots);
    }
}

void vm_do_mmu_mprotect(struct mm_address_space *mm, void *address, size_t nr_pgs, int old_prots,
                        int new_prots)
{
    unsigned long start = (unsigned long) address;
    unsigned long end = start + (nr_pgs << PAGE_SHIFT);
    struct tlbi_tracker tlbi;
    tlbi_tracker_init(&tlbi);

    pgd_protect_range(&tlbi, pgd_offset(mm, start), start, end, new_prots);

    if (tlbi_active(&tlbi))
        tlbi_end_batch(&tlbi);
}

static int pte_fork_range(struct tlbi_tracker *tlbi, pte_t *pte, pte_t *old_pte,
                          unsigned long start, unsigned long end, struct mm_address_space *mm,
                          struct vm_area_struct *old_vma)
{
    /* Let's lock the page tables. It actually *does* matter in our case, because we must have
     * stable ptes (one can imagine a situation where a shared pte getting wp'd races and we get a
     * writable mapping without the page being dirty). */
    spin_lock(&mm->page_table_lock);
    unsigned long next_start;
    for (; start < end; pte++, old_pte++, start = next_start)
    {
        next_start = min(pte_addr_end(start), end);
        pte_t old = *old_pte;
        if (pte_none(old))
            continue;
        if (!pte_present(old))
        {
            __swap_inc_map(pte_to_swp_entry(old));
            set_pte(pte, old);
            continue;
        }

        if (!vma_is_pfnmap(old_vma) && !pte_special(old))
            page_add_mapcount(phys_to_page(pte_addr(old)));

        if (!pte_protnone(old) && vma_private(old_vma) && pte_write(old))
        {
            /* We must CoW MAP_PRIVATE */
            set_pte(old_pte, pte_wrprotect(old));
            set_pte(pte, *old_pte);
            tlbi_update_page_prots(tlbi, start, old, *pte);
        }
        else
        {
            set_pte(pte, old);
        }

        increment_vm_stat(mm, resident_set_size, PAGE_SIZE);
    }

    spin_unlock(&mm->page_table_lock);
    return 0;
}

static int pmd_fork_huge(struct tlbi_tracker *tlbi, pmd_t *pmd, pmd_t *old_pmd, unsigned long start,
                         struct mm_address_space *mm, struct vm_area_struct *old_vma)
{
    struct folio *folio = NULL;
    pmd_t old = *old_pmd;

    spin_lock(&mm->page_table_lock);

    if (!vma_is_pfnmap(old_vma))
    {
        folio = phys_to_folio(pmd_addr(old));
        folio_add_mapcount(folio);
    }

    if (!pmd_protnone(old) && vma_private(old_vma))
    {
        /* We must CoW MAP_PRIVATE */
        set_pmd(old_pmd, pmd_wrprotect(old));
        set_pmd(pmd, *old_pmd);
        tlbi_update_page_prots_huge_pmd(tlbi, start, old, *pmd);
    }
    else
    {
        set_pmd(pmd, old);
    }

    increment_vm_stat(mm, resident_set_size, PMD_SIZE);
    spin_unlock(&mm->page_table_lock);
    return 0;
}

static int pmd_fork_range(struct tlbi_tracker *tlbi, pmd_t *pmd, pmd_t *old_pmd,
                          unsigned long start, unsigned long end, struct mm_address_space *mm,
                          struct vm_area_struct *old_vma)
{
    unsigned long next_start;
    int err;

    for (; start < end; pmd++, old_pmd++, start = next_start)
    {
        next_start = min(pmd_addr_end(start), end);
        if (pmd_none(*old_pmd))
            continue;

        if (pmd_huge(*old_pmd))
        {
            err = pmd_fork_huge(tlbi, pmd, old_pmd, start, mm, old_vma);
            if (err < 0)
                return err;
            continue;
        }

        pte_t *pte = pte_get_or_alloc(pmd, start, mm);
        if (!pte)
            return -ENOMEM;

        err = pte_fork_range(tlbi, pte, pte_offset(old_pmd, start), start, next_start, mm, old_vma);
        if (err < 0)
            return err;
    }

    return 0;
}

static int pud_fork_range(struct tlbi_tracker *tlbi, pud_t *pud, pud_t *old_pud,
                          unsigned long start, unsigned long end, struct mm_address_space *mm,
                          struct vm_area_struct *old_vma)
{
    unsigned long next_start;
    for (; start < end; pud++, old_pud++, start = next_start)
    {
        next_start = min(pud_addr_end(start), end);
        if (pud_none(*old_pud))
            continue;
        pmd_t *pmd = pmd_get_or_alloc(pud, start, mm);
        if (!pmd)
            return -ENOMEM;
        /* TODO: Huge page splitting not supported yet... */
        DCHECK(!pud_huge(*pud));
        int err =
            pmd_fork_range(tlbi, pmd, pmd_offset(old_pud, start), start, next_start, mm, old_vma);
        if (err < 0)
            return err;
    }

    return 0;
}

static int p4d_fork_range(struct tlbi_tracker *tlbi, p4d_t *p4d, p4d_t *old_p4d,
                          unsigned long start, unsigned long end, struct mm_address_space *mm,
                          struct vm_area_struct *old_vma)
{
    unsigned long next_start;
    for (; start < end; p4d++, old_p4d++, start = next_start)
    {
        next_start = min(p4d_addr_end(start), end);
        if (p4d_none(*old_p4d))
            continue;
        pud_t *pud = pud_get_or_alloc(p4d, start, mm);
        if (!pud)
            return -ENOMEM;

        /* TODO: Huge page splitting not supported yet... */
        DCHECK(!p4d_huge(*p4d));
        int err =
            pud_fork_range(tlbi, pud, pud_offset(old_p4d, start), start, next_start, mm, old_vma);
        if (err < 0)
            return -ENOMEM;
    }

    return 0;
}

static int pgd_fork_range(struct tlbi_tracker *tlbi, pgd_t *pgd, pgd_t *old_pgd,
                          unsigned long start, unsigned long end, struct mm_address_space *mm,
                          struct vm_area_struct *old_vma)
{
    unsigned long next_start;
    for (; start < end; pgd++, old_pgd++, start = next_start)
    {
        next_start = min(pgd_addr_end(start), end);
        if (pgd_none(*old_pgd))
            continue;
        p4d_t *p4d = p4d_get_or_alloc(pgd, start, mm);
        if (!p4d)
            return -ENOMEM;

        int err =
            p4d_fork_range(tlbi, p4d, p4d_offset(old_pgd, start), start, next_start, mm, old_vma);
        if (err < 0)
            return err;
    }

    return 0;
}

/**
 * @brief Fork MMU page tables
 *
 * @param old_vma Old vm_area_struct
 * @param mm Current address space
 * @return 0 on success, negative error codes
 */
int mmu_fork_tables(struct vm_area_struct *old_vma, struct mm_address_space *mm)
{
    unsigned long start = old_vma->vm_start;
    unsigned long end = old_vma->vm_end;
    int err;
    struct tlbi_tracker tlbi;
    tlbi_tracker_init(&tlbi);

    /* Note: We can't take the page table spinlock here (hold time is too long, too many memory
     * allocations may happen). We'll rely on holding the mm lock exclusively. Page table
     * lifetime atm is a bit iffy, needs some solid rethinking. */
    err = pgd_fork_range(&tlbi, pgd_offset(mm, start), pgd_offset(old_vma->vm_mm, start), start,
                         end, mm, old_vma);

    if (tlbi_active(&tlbi))
        tlbi_end_batch(&tlbi);
    return err;
}

int try_to_unmap_one(struct page *page, struct vm_area_struct *vma,
                     unsigned long addr) NO_THREAD_SAFETY_ANALYSIS
{
    struct mm_address_space *mm = vma->vm_mm;
    pte_t *pte, oldpte;
    struct tlbi_tracker tlbi;
    struct spinlock *lock;

    tlbi_tracker_init(&tlbi);

    pte = ptep_get_locked(vma->vm_mm, addr, &lock);
    if (!pte)
        return 0;

    if (!pte_present(*pte) && !pte_protnone(*pte))
        goto out;

    oldpte = *pte;

    if (pte_addr(oldpte) != (unsigned long) page_to_phys(page))
    {
        /* Not the same page, don't unmap */
        goto out;
    }

    DCHECK(!pte_special(oldpte));
    /* Ref the page. This makes sure it _doesnt_ go away after the sub_mapcount. We need this so
     * the page isn't freed before the tlbi. */
    page_ref(page);
    page_sub_mapcount(page);

    if (page_test_swap(page))
    {
        if (pte_dirty(oldpte))
            filemap_mark_dirty(page, page->pageoff);
        swap_inc_map(page);
        /* Replace this pte with a swap pte */
        set_pte(pte, __pte(page->priv));
    }
    else
        set_pte(pte, __pte(0));
    if (pte_present(oldpte) || pte_protnone(oldpte))
    {
        if (!pte_protnone(oldpte))
            tlbi_remove_page(&tlbi, addr, page);
        decrement_vm_stat(mm, resident_set_size, PAGE_SIZE);
    }

out:
    spin_unlock(lock);

    if (tlbi_active(&tlbi))
        tlbi_end_batch(&tlbi);

    return 0;
}

pte_t *ptep_get_locked(struct mm_address_space *mm, unsigned long addr, struct spinlock **lock)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd))
        return NULL;

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d))
        return NULL;

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud))
        return NULL;
    DCHECK(!pud_huge(*pud));

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd))
        return NULL;
    DCHECK(!pmd_huge(*pmd));
    return pte_offset_lock(pmd, addr, mm, lock);
}

int pgtable_prealloc(struct mm_address_space *mm, unsigned long virt)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    pgd = pgd_offset(mm, virt);

    p4d = p4d_get_or_alloc(pgd, virt, mm);
    if (unlikely(!p4d))
        return -ENOMEM;

    pud = pud_get_or_alloc(p4d, virt, mm);
    if (unlikely(!pud))
        return -ENOMEM;

    pmd = pmd_get_or_alloc(pud, virt, mm);
    if (unlikely(!pmd))
        return -ENOMEM;

    pte = pte_get_or_alloc(pmd, virt, mm);
    if (unlikely(!pte))
        return -ENOMEM;
    return 0;
}

static bool wp_may_reuse_old(struct page *page)
{
    /* Check if there are circumstances to use the old page as the new dirtied page. Basically,
     * we want to check for refcount/mapcount while also being careful about the page going away
     * at some point. Page tables are locked. */
    if (page->ref > 1U + page_test_swap(page))
        return false;
    if (page_mapcount(page) > 1)
        return false;
    /* Try-lock it, and recheck these conditions. The swap tests for instance are racy without
     * the lock. */
    if (!try_lock_page(page))
        return false;
    if (page->ref > 1U + page_test_swap(page))
        goto no_unlock;
    if (page_test_swap(page))
        goto no_unlock;
    if (page_mapcount(page) > 1)
        goto no_unlock;

    unlock_page(page);
    return true;
no_unlock:
    unlock_page(page);
    return false;
}

static int do_reuse_wp(struct vm_pf_context *context, struct page *oldp, pte_t *pte,
                       struct spinlock *lock)
{
    set_pte(pte, pte_mkwrite(*pte));
    /* We keep the same PFN. This is okay. We can get away with a core-local TLB invalidation.
     * Other cores either re-fetch the correct entry from the TLB, or take a spurious fault.
     * Either situation is faster than possibly IPI'ing or broadcasting a TLBI. */
    spin_unlock(lock);
    tlbi_upgrade_pte_prots(context->entry->vm_mm, context->vpage);
    return 0;
}

int do_wp_page(struct vm_pf_context *context)
{
    struct page *oldp = phys_to_page(pte_addr(context->oldpte));
    bool was_zeropage = oldp == vm_get_zero_page();
    struct page *new_page;
    pte_t *ptep;
    u64 phys;
    struct spinlock *lock = NULL;
    struct tlbi_tracker tlbi;
    struct anon_vma *anon = anon_vma_prepare(context->entry);
    if (!anon)
        return -ENOMEM;

    ptep = ptep_get_locked(context->entry->vm_mm, context->vpage, &lock);
    if (ptep->pte != context->oldpte.pte)
    {
        spin_unlock(lock);
        return 0;
    }

    if (!was_zeropage && wp_may_reuse_old(oldp))
        return do_reuse_wp(context, oldp, ptep, lock);

    spin_unlock(lock);

    new_page = alloc_page(GFP_KERNEL | (was_zeropage ? 0 : PAGE_ALLOC_NO_ZERO));
    if (!new_page)
        return -ENOMEM;

    if (!was_zeropage)
        copy_page_to_page(page_to_phys(new_page), page_to_phys(oldp));

    new_page->owner = (struct vm_object *) anon;
    new_page->pageoff = context->vpage;
    page_set_dirty(new_page);
    page_set_anon(new_page);
    page_add_lru(new_page);

    tlbi_tracker_init(&tlbi);

    spin_lock(lock);
    if (ptep->pte != context->oldpte.pte)
    {
        page_unref(new_page);
        goto out;
    }

    DCHECK(pte_present(*ptep));

    if (!was_zeropage)
    {
        /* Ref the page, so it doesn't go away before the tlbi */
        page_ref(oldp);
        page_sub_mapcount(oldp);
    }

    phys = (u64) page_to_phys(new_page);
    page_add_mapcount(new_page);
    set_pte(ptep, pte_mkpte(phys, calc_pgprot(phys, context->entry->vm_flags)));
    tlbi_remove_page(&tlbi, context->vpage, !was_zeropage ? oldp : NULL);
    page_unref(new_page);
out:
    if (tlbi_active(&tlbi))
        tlbi_end_batch(&tlbi);
    spin_unlock(lock);
    return 0;
}
