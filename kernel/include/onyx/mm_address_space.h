/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_MM_ADDRESS_SPACE_H
#define _ONYX_MM_ADDRESS_SPACE_H

#include <lib/binary_search_tree.h>

#include <onyx/cpumask.h>
#include <onyx/maple_tree.h>
#include <onyx/ref.h>
#include <onyx/rwlock.h>

#include <platform/vm.h>

#ifdef __cplusplus
// clang-format off
#define CPP_DFLINIT {}
// clang-format on
#else
#define CPP_DFLINIT
#endif

#define AT_SAVED_AUXV_LEN 20

/**
 * @brief An mm_address_space represents an address space inside the kernel and stores
 * all kinds of relevant data on it, like the owner process, a tree of vm_area_structs, locks
 * various statistics, etc.
 *
 */
struct mm_address_space
{
    refcount_t mm_count;
    refcount_t mm_users;
    /* Virtual address space WAVL tree */
    struct maple_tree region_tree;
    unsigned long start;
    unsigned long end;
    struct rwlock vm_lock;

    /* mmap(2) base */
    void *mmap_base;

    /* Process' brk */
    void *brk;

    size_t virtual_memory_size;
    size_t resident_set_size;
    size_t shared_set_size;
    size_t page_faults;
    size_t page_tables_size;

    unsigned long arg_start;
    unsigned long arg_end;

    unsigned long saved_auxv[AT_SAVED_AUXV_LEN * 2];

    struct arch_mm_address_space arch_mmu;

    // The active mask keeps track of where the address space is running.
    // This serves as an optimisation when doing a TLB shootdown, as it lets us
    // limit the shootdowns to CPUs where the address space is active instead of every CPU.
    struct cpumask active_mask;

    struct spinlock page_table_lock;

#ifdef __cplusplus
    mm_address_space &operator=(mm_address_space &&as)
    {
        start = as.start;
        end = as.end;
        mmap_base = as.mmap_base;
        brk = as.brk;
        virtual_memory_size = as.virtual_memory_size;
        resident_set_size = as.resident_set_size;
        shared_set_size = as.shared_set_size;
        page_faults = as.page_faults;
        page_tables_size = as.page_tables_size;
        arch_mmu = as.arch_mmu;
        active_mask = cul::move(as.active_mask);
        return *this;
    }
#endif
};

#define increment_vm_stat(as, name, amount) __sync_add_and_fetch(&as->name, amount)
#define decrement_vm_stat(as, name, amount) __sync_sub_and_fetch(&as->name, amount)

__BEGIN_CDECLS

struct mm_address_space *mm_create(void);
struct mm_address_space *mm_fork(void);

static inline void mmget(struct mm_address_space *mm)
{
    refcount_inc(&mm->mm_users);
}

static inline void mmgrab(struct mm_address_space *mm)
{
    refcount_inc(&mm->mm_count);
}

void __mmdrop(struct mm_address_space *mm);
void __mmput(struct mm_address_space *mm);

static inline void mmdrop(struct mm_address_space *mm)
{
    if (refcount_dec_and_test(&mm->mm_count))
        __mmdrop(mm);
}

static inline void mmput(struct mm_address_space *mm)
{
    if (refcount_dec_and_test(&mm->mm_users))
        __mmput(mm);
}

__END_CDECLS

#endif
