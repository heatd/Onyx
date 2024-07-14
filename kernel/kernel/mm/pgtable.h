/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_PGTABLE_H
#define _ONYX_PGTABLE_H

#include "pgtable-arch.h"

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

#endif
