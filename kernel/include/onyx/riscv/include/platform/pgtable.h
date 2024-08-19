/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_PGTABLE_ARCH_H
#define _ONYX_PGTABLE_ARCH_H

#include <stdbool.h>

#include <onyx/atomic.h>
#include <onyx/mm_address_space.h>
#include <onyx/types.h>
#include <onyx/vm.h>

__BEGIN_CDECLS

typedef u64 pgdval_t;
typedef u64 p4dval_t;
typedef u64 pudval_t;
typedef u64 pmdval_t;
typedef u64 pteval_t;
typedef u64 pgprotval_t;

#define PTE_GET_ADDR(n) ((n >> 10) << 12)
#define _PAGE_PRESENT   (1 << 0)
#define _PAGE_READ      (1 << 1)
#define _PAGE_WRITE     (1 << 2)
#define _PAGE_EXEC      (1 << 3)
#define _PAGE_USER      (1 << 4)
#define _PAGE_GLOBAL    (1 << 5)
#define _PAGE_ACCESSED  (1 << 6)
#define _PAGE_DIRTY     (1 << 7)
/* Use one of the ignored bits as SPECIAL. This will annotate zero page mappings (so we don't
 * increment mapcount on zero_page and thus blow it up). add_mapcount and sub_mapcount will not be
 * called on these struct pages. */
#define _PAGE_SPECIAL   (1 << 8)

#define _PAGE_HUGE     (_PAGE_WRITE | _PAGE_EXEC | _PAGE_READ)
#define _PAGE_PROTNONE _PAGE_GLOBAL

typedef struct pgd
{
    pgdval_t pgd;
} pgd_t;

typedef struct p4d
{
    p4dval_t p4d;
} p4d_t;

typedef struct pud
{
    pudval_t pud;
} pud_t;

typedef struct pmd
{
    pmdval_t pmd;
} pmd_t;

typedef struct pte
{
    pteval_t pte;
} pte_t;

typedef struct pgprot
{
    pgprotval_t pgprot;
} pgprot_t;

#define PTRS_PER_PGD 512
#define PGD_SHIFT    39

#define PTRS_PER_P4D 1
#define P4D_SHIFT    39

#define PTRS_PER_PUD 512
#define PUD_SHIFT    30

#define PTRS_PER_PMD 512
#define PMD_SHIFT    21

#define PTRS_PER_PTE 512
#define PTE_SHIFT    12

#define __tovirt(x) (void *) (((uintptr_t) (x)) + PHYS_BASE)

static inline unsigned long pgd_index(unsigned long addr)
{
    return (addr >> PGD_SHIFT) & (PTRS_PER_PGD - 1);
}

static inline pgd_t *pgd_offset(struct mm_address_space *mm, unsigned long addr)
{
    return (pgd_t *) __tovirt(mm->arch_mmu.top_pt) + pgd_index(addr);
}

#define pgd_val(x)    ((x).pgd)
#define p4d_val(x)    ((x).p4d)
#define pud_val(x)    ((x).pud)
#define pmd_val(x)    ((x).pmd)
#define pte_val(x)    ((x).pte)
#define pgprot_val(x) ((x).pgprot)

#define __pgd(x)    ((pgd_t){(x)})
#define __p4d(x)    ((p4d_t){(x)})
#define __pud(x)    ((pud_t){(x)})
#define __pmd(x)    ((pmd_t){(x)})
#define __pte(x)    ((pte_t){(x)})
#define __pgprot(x) ((pgprot_t){(x)})

static inline unsigned long p4d_index(unsigned long addr)
{
    return (addr >> P4D_SHIFT) & (PTRS_PER_P4D - 1);
}

static inline unsigned long pgd_addr(pgd_t pgd)
{
    return PTE_GET_ADDR(pgd_val(pgd));
}

static inline unsigned long pud_index(unsigned long addr)
{
    return (addr >> PUD_SHIFT) & (PTRS_PER_PUD - 1);
}

static inline unsigned long p4d_addr(p4d_t pgd)
{
    return PTE_GET_ADDR(p4d_val(pgd));
}

static inline pud_t *pud_offset(p4d_t *p4d, unsigned long addr)
{
    return (pud_t *) __tovirt(p4d_addr(*p4d)) + pud_index(addr);
}

static inline unsigned long pmd_index(unsigned long addr)
{
    return (addr >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
}

static inline unsigned long pud_addr(pud_t pgd)
{
    return PTE_GET_ADDR(pud_val(pgd));
}

static inline pmd_t *pmd_offset(pud_t *pud, unsigned long addr)
{
    return (pmd_t *) __tovirt(pud_addr(*pud)) + pmd_index(addr);
}

static inline unsigned long pte_index(unsigned long addr)
{
    return (addr >> PTE_SHIFT) & (PTRS_PER_PTE - 1);
}

static inline unsigned long pmd_addr(pmd_t pgd)
{
    return PTE_GET_ADDR(pmd_val(pgd));
}

static inline pte_t *pte_offset(pmd_t *pmd, unsigned long addr)
{
    return (pte_t *) __tovirt(pmd_addr(*pmd)) + pte_index(addr);
}

static inline unsigned long pte_addr(pte_t pgd)
{
    return PTE_GET_ADDR(pte_val(pgd));
}

static inline bool p4d_none(p4d_t p4d)
{
    return p4d_val(p4d) == 0;
}

static inline bool pud_none(pud_t pud)
{
    return pud_val(pud) == 0;
}

static inline bool pmd_none(pmd_t pmd)
{
    return pmd_val(pmd) == 0;
}

static inline bool pte_none(pte_t pte)
{
    return pte_val(pte) == 0;
}

static inline bool p4d_present(p4d_t p4d)
{
    return p4d_val(p4d) & _PAGE_PRESENT;
}

static inline bool pud_present(pud_t pud)
{
    return pud_val(pud) & _PAGE_PRESENT;
}

static inline bool pmd_present(pmd_t pmd)
{
    return pmd_val(pmd) & _PAGE_PRESENT;
}

static inline bool pte_present(pte_t pte)
{
    return pte_val(pte) & (_PAGE_PRESENT | _PAGE_PROTNONE);
}

#define KERNEL_PGTBL (_PAGE_PRESENT)
#define USER_PGTBL   (KERNEL_PGTBL)

static inline pte_t pte_mkpte(u64 phys, pgprot_t prot)
{
    return __pte(((phys >> PAGE_SHIFT) << 10) | pgprot_val(prot));
}

static inline pmd_t pmd_mkpmd(u64 phys, pgprot_t prot)
{
    return __pmd(((phys >> PAGE_SHIFT) << 10) | pgprot_val(prot));
}

static inline pud_t pud_mkpud(u64 phys, pgprot_t prot)
{
    return __pud(((phys >> PAGE_SHIFT) << 10) | pgprot_val(prot));
}

static inline p4d_t p4d_mkp4d(u64 phys, pgprot_t prot)
{
    return __p4d(((phys >> PAGE_SHIFT) << 10) | pgprot_val(prot));
}

static inline pgd_t pgd_mkpgd(u64 phys, pgprot_t prot)
{
    return __pgd(((phys >> PAGE_SHIFT) << 10) | pgprot_val(prot));
}

static inline bool pte_special(pte_t pte)
{
    return pte_val(pte) & _PAGE_SPECIAL;
}

static inline bool pte_accessed(pte_t pte)
{
    return pte_val(pte) & _PAGE_ACCESSED;
}

static inline bool pte_user(pte_t pte)
{
    return pte_val(pte) & _PAGE_USER;
}

static inline bool pte_write(pte_t pte)
{
    return pte_val(pte) & _PAGE_WRITE;
}

static inline bool pte_exec(pte_t pte)
{
    return pte_val(pte) & _PAGE_EXEC;
}

static inline bool pte_dirty(pte_t pte)
{
    return pte_val(pte) & _PAGE_DIRTY;
}

static inline bool pte_global(pte_t pte)
{
    return pte_val(pte) & _PAGE_GLOBAL;
}

static void set_pgd(pgd_t *pgd, pgd_t val)
{
    WRITE_ONCE(pgd_val(*pgd), pgd_val(val));
}
#define set_pgd set_pgd

static inline pte_t pte_mkyoung(pte_t pte)
{
    return __pte(pte_val(pte) & ~_PAGE_ACCESSED);
}

static inline pte_t pte_mkwrite(pte_t pte)
{
    return __pte(pte_val(pte) | _PAGE_WRITE);
}

/* PML4-level hugepages not supported on x86, for now... */
#define ARCH_HUGE_PUD_SUPPORT 1
#define ARCH_HUGE_PMD_SUPPORT 1

static inline bool pud_huge(pud_t pud)
{
    return pud_val(pud) & _PAGE_HUGE;
}

static inline bool pmd_huge(pmd_t pmd)
{
    return pmd_val(pmd) & _PAGE_HUGE;
}

static inline bool pud_user(pud_t pud)
{
    return pud_val(pud) & _PAGE_USER;
}

static inline bool pud_write(pud_t pud)
{
    return pud_val(pud) & _PAGE_WRITE;
}

static inline bool pud_exec(pud_t pud)
{
    return pud_val(pud) & _PAGE_EXEC;
}

static inline bool pud_dirty(pud_t pud)
{
    return pud_val(pud) & _PAGE_DIRTY;
}

static inline bool pud_accessed(pud_t pud)
{
    return pud_val(pud) & _PAGE_ACCESSED;
}

static inline bool pud_global(pud_t pud)
{
    return pud_val(pud) & _PAGE_GLOBAL;
}

static inline bool pmd_user(pmd_t pmd)
{
    return pmd_val(pmd) & _PAGE_USER;
}

static inline bool pmd_write(pmd_t pmd)
{
    return pmd_val(pmd) & _PAGE_WRITE;
}

static inline bool pmd_exec(pmd_t pmd)
{
    return pmd_val(pmd) & _PAGE_EXEC;
}

static inline bool pmd_dirty(pmd_t pmd)
{
    return pmd_val(pmd) & _PAGE_DIRTY;
}

static inline bool pmd_accessed(pmd_t pmd)
{
    return pmd_val(pmd) & _PAGE_ACCESSED;
}

static inline bool pmd_global(pmd_t pmd)
{
    return pmd_val(pmd) & _PAGE_GLOBAL;
}

#define pud_folded() (0)
#define pmd_folded() (0)

static inline pte_t pte_wrprotect(pte_t pte)
{
    return __pte(pte_val(pte) & ~_PAGE_WRITE);
}

static inline pgprot_t calc_pgprot(u64 phys, u64 prots)
{
    bool special_mapping = phys == (u64) page_to_phys(vm_get_zero_page());
    pgprotval_t page_prots = (prots & VM_EXEC ? _PAGE_EXEC : 0) |
                             (prots & VM_WRITE ? _PAGE_WRITE : 0) |
                             (prots & (VM_READ | VM_WRITE) ? _PAGE_READ : 0) |
                             (prots & VM_USER ? _PAGE_USER : _PAGE_GLOBAL) | _PAGE_PRESENT |
                             (special_mapping ? _PAGE_SPECIAL : 0);

    if (!(prots & (VM_READ | VM_WRITE | VM_EXEC)))
    {
        page_prots &= ~_PAGE_PRESENT;
        page_prots |= _PAGE_PROTNONE;
    }

    return __pgprot(page_prots);
}

static inline bool pte_protnone(pte_t pte)
{
    return (pte_val(pte) & (_PAGE_PRESENT | _PAGE_PROTNONE)) == _PAGE_PROTNONE;
}

#define ARCH_SWAP_NR_TYPES  16
#define ARCH_SWP_TYPE_SHIFT 60
#define ARCH_SWP_OFF_SHIFT  6
#define ARCH_SWP_OFF_MASK   ((1UL << ARCH_SWP_TYPE_SHIFT) - 1)

/* Swap entry format:  64 | type (4 bits) 60 | offset (in hw pages) | PROT_NONE (aliases with G) |
 * ... | 0 (PRESENT). PROT_NONE must not conflict with any important permission or A/D (because
 * we'll use it after faulting it back). */
#define SWP_TYPE(entry)   ((entry).swp >> ARCH_SWP_TYPE_SHIFT)
#define SWP_OFFSET(entry) (((entry).swp & ARCH_SWP_OFF_MASK) >> ARCH_SWP_OFF_SHIFT)
#define SWP_ENTRY(type, offset) \
    ((swp_entry_t){.swp = (type) << ARCH_SWP_TYPE_SHIFT | (offset) << ARCH_SWP_OFF_SHIFT})

#define pte_to_swp_entry(pte) ((swp_entry_t){.swp = pte_val(pte)})

/**
 * @brief Invalidate the TLB after upgrading PTE protection
 * Invalidates the TLB when upgrading PTE permissions. It isn't required to sync this invalidation
 * with other cores.
 * @param mm Address space
 * @param virt Virtual address to invalidate
 */
void tlbi_upgrade_pte_prots(struct mm_address_space *mm, unsigned long virt);

/**
 * @brief Handle a seemingly spurious fault locally
 * Make sure we sync the TLB when we find a spurious fault.
 * @param mm Address space
 * @param virt Virtual address to invalidate
 */
void tlbi_handle_spurious_fault_pte(struct mm_address_space *mm, unsigned long virt);

#include <onyx/mm/pgtable-nop4d.h>

__END_CDECLS

#endif
