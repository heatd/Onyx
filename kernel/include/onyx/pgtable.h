/*
 * Copyright (c) 2024 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_PGTABLE_H
#define _ONYX_PGTABLE_H

#include <onyx/compiler.h>
#include <onyx/list.h>

__BEGIN_CDECLS

/* platform/pgtable needs to see this type */
typedef unsigned long swpval_t;
typedef struct
{
    swpval_t swp;
} swp_entry_t;

#define swpval_to_swp_entry(swpval) ((swp_entry_t){.swp = (swpval)})

#include <platform/pgtable.h>

#ifndef set_pgd
static void set_pgd(pgd_t *pgd, pgd_t val)
{
    WRITE_ONCE(pgd_val(*pgd), pgd_val(val));
}
#define set_pgd set_pgd
#endif

#ifndef set_p4d
static void set_p4d(p4d_t *p4d, p4d_t val)
{
    WRITE_ONCE(p4d_val(*p4d), p4d_val(val));
}
#define set_p4d set_p4d
#endif

#ifndef set_pud
static void set_pud(pud_t *pud, pud_t val)
{
    WRITE_ONCE(pud_val(*pud), pud_val(val));
}
#define set_pud set_pud
#endif

#ifndef set_pmd
static void set_pmd(pmd_t *pmd, pmd_t val)
{
    WRITE_ONCE(pmd_val(*pmd), pmd_val(val));
}
#define set_pmd set_pmd
#endif

#ifndef set_pte
static void set_pte(pte_t *pte, pte_t val)
{
    WRITE_ONCE(pte_val(*pte), pte_val(val));
}
#define set_pgd set_pgd
#endif

static inline bool pte_cmpxchg(pte_t *pte, pte_t *expected, pte_t desired)
{
    return __atomic_compare_exchange_n(&pte->pte, &expected->pte, desired.pte, false,
                                       __ATOMIC_RELAXED, __ATOMIC_RELAXED);
}

/* Dummy fallbacks for architectures that don't support certain huge page levels */

#ifndef ARCH_HUGE_P4D_SUPPORT

static inline bool p4d_huge(p4d_t p4d)
{
    return false;
}

static inline bool p4d_user(p4d_t p4d)
{
    return false;
}

static inline bool p4d_write(p4d_t p4d)
{
    return false;
}

static inline bool p4d_exec(p4d_t p4d)
{
    return false;
}

static inline bool p4d_dirty(p4d_t p4d)
{
    return false;
}

static inline bool p4d_accessed(p4d_t p4d)
{
    return false;
}

static inline bool p4d_global(p4d_t p4d)
{
    return false;
}

#endif

#ifndef ARCH_HUGE_PUD_SUPPORT

static inline bool pud_huge(pud_t pud)
{
    return false;
}

static inline bool pud_user(pud_t pud)
{
    return false;
}

static inline bool pud_write(pud_t pud)
{
    return false;
}

static inline bool pud_exec(pud_t pud)
{
    return false;
}

static inline bool pud_dirty(pud_t pud)
{
    return false;
}

static inline bool pud_accessed(pud_t pud)
{
    return false;
}

static inline bool pud_global(pud_t pud)
{
    return false;
}

#endif

#ifndef ARCH_HUGE_PMD_SUPPORT

static inline bool pmd_huge(pmd_t pmd)
{
    return false;
}

static inline bool pmd_user(pmd_t pmd)
{
    return false;
}

static inline bool pmd_write(pmd_t pmd)
{
    return false;
}

static inline bool pmd_exec(pmd_t pmd)
{
    return false;
}

static inline bool pmd_dirty(pmd_t pmd)
{
    return false;
}

static inline bool pmd_accessed(pmd_t pmd)
{
    return false;
}

static inline bool pmd_global(pmd_t pmd)
{
    return false;
}

#endif

#define PGD_SIZE (1UL << PGD_SHIFT)
#define P4D_SIZE (1UL << P4D_SHIFT)
#define PUD_SIZE (1UL << PUD_SHIFT)
#define PMD_SIZE (1UL << PMD_SHIFT)
#define PTE_SIZE (1UL << PTE_SHIFT)

static inline unsigned long pgd_addr_end(unsigned long addr)
{
    /* We need to be careful with overflows... */
    unsigned long end = (addr & -PGD_SIZE) + PGD_SIZE;
    return end < addr ? -1UL : end;
}

static inline unsigned long p4d_addr_end(unsigned long addr)
{
    /* We need to be careful with overflows... */
    unsigned long end = (addr & -P4D_SIZE) + P4D_SIZE;
    return end < addr ? -1UL : end;
}

static inline unsigned long pud_addr_end(unsigned long addr)
{
    /* We need to be careful with overflows... */
    unsigned long end = (addr & -PUD_SIZE) + PUD_SIZE;
    return end < addr ? -1UL : end;
}

static inline unsigned long pmd_addr_end(unsigned long addr)
{
    /* We need to be careful with overflows... */
    unsigned long end = (addr & -PMD_SIZE) + PMD_SIZE;
    return end < addr ? -1UL : end;
}

static inline unsigned long pte_addr_end(unsigned long addr)
{
    /* We need to be careful with overflows... */
    unsigned long end = (addr & -PTE_SIZE) + PTE_SIZE;
    return end < addr ? -1UL : end;
}

struct tlbi_tracker
{
    /* Somewhat primitive, but will do for the time being... */
    unsigned long start, end;
    struct list_head batches;
    bool active;
};

static inline void tlbi_tracker_init(struct tlbi_tracker *tlbi)
{
    tlbi->start = tlbi->end = 0;
    tlbi->active = false;
    INIT_LIST_HEAD(&tlbi->batches);
}

void tlbi_end_batch(struct tlbi_tracker *tlbi);
bool tlbi_active(struct tlbi_tracker *tlbi);

pte_t *ptep_get_locked(struct mm_address_space *mm, unsigned long addr, struct spinlock **lock);
int pgtable_prealloc(struct mm_address_space *mm, unsigned long virt);
int zap_page_range(unsigned long start, unsigned long end, struct vm_area_struct *vma);
int vma_unmap(struct mm_address_space *mm, void *addr, size_t pages, struct vm_area_struct *vma,
              struct tlbi_tracker *tlbi);

p4d_t *p4d_get_or_alloc(pgd_t *pgd, unsigned long addr, struct mm_address_space *mm);
pud_t *pud_get_or_alloc(p4d_t *p4d, unsigned long addr, struct mm_address_space *mm);
pmd_t *pmd_get_or_alloc(pud_t *pud, unsigned long addr, struct mm_address_space *mm);
pte_t *pte_get_or_alloc(pmd_t *pmd, unsigned long addr, struct mm_address_space *mm);

#define pmd_lockptr(mm, pmd) (&(mm)->page_table_lock)
#define pte_lockptr(pte, mm) (&(mm)->page_table_lock)

#define pte_lock(pte, mm)   (spin_lock(pte_lockptr(pte, mm)))
#define pte_unlock(pte, mm) (spin_unlock(pte_lockptr(pte, mm)))

static inline pte_t *pte_offset_lock(pmd_t *pmd, unsigned long addr, struct mm_address_space *mm,
                                     struct spinlock **lock)
{
    pte_t *pte;

    pte = pte_offset(pmd, addr);
    *lock = pte_lockptr(pte, mm);
    spin_lock(*lock);
    return pte;
}

static inline pte_t ptep_get_lockless(pte_t *pte)
{
    return __pte(READ_ONCE(pte->pte));
}

static inline pmd_t pmdp_get_lockless(pmd_t *pmd)
{
    return __pmd(READ_ONCE(pmd->pmd));
}

__END_CDECLS

#endif
