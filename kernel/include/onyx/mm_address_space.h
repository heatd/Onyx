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
#include <onyx/mutex.h>

#include <platform/vm.h>

#ifdef __cplusplus
#include <onyx/refcount.h>

#include <onyx/expected.hpp>
// clang-format off
#define CPP_DFLINIT {}
// clang-format on
#else
#define CPP_DFLINIT
#endif

/**
 * @brief An mm_address_space represents an address space inside the kernel and stores
 * all kinds of relevant data on it, like the owner process, a tree of vm_area_structs, locks
 * various statistics, etc.
 *
 */
struct mm_address_space
#ifdef __cplusplus
    : public refcountable
#endif
{
#ifndef __cplusplus
    void *__vtable;
    unsigned long refc;
#endif
    /* Virtual address space WAVL tree */
    struct maple_tree region_tree;
    unsigned long start CPP_DFLINIT;
    unsigned long end CPP_DFLINIT;
    struct mutex vm_lock CPP_DFLINIT;

    /* mmap(2) base */
    void *mmap_base CPP_DFLINIT;

    /* Process' brk */
    void *brk CPP_DFLINIT;

    size_t virtual_memory_size CPP_DFLINIT;
    size_t resident_set_size CPP_DFLINIT;
    size_t shared_set_size CPP_DFLINIT;
    size_t page_faults CPP_DFLINIT;
    size_t page_tables_size CPP_DFLINIT;

    struct arch_mm_address_space arch_mmu CPP_DFLINIT;

    // The active mask keeps track of where the address space is running.
    // This serves as an optimisation when doing a TLB shootdown, as it lets us
    // limit the shootdowns to CPUs where the address space is active instead of every CPU.
    struct cpumask active_mask CPP_DFLINIT;

    struct spinlock page_table_lock CPP_DFLINIT;

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

    constexpr mm_address_space()
    {
        spinlock_init(&page_table_lock);
        region_tree = MTREE_INIT(region_tree, MT_FLAGS_ALLOC_RANGE | MT_FLAGS_LOCK_EXTERN);
    }

    /**
     * @brief Creates a new standalone address space
     *
     * @return Ref guard to a mm_address_space, or a negative status code
     */
    static expected<ref_guard<mm_address_space>, int> create();

    /**
     * @brief Creates a new standalone address space by forking
     *
     * @return Ref guard to a mm_address_space, or a negative status code
     */
    static expected<ref_guard<mm_address_space>, int> fork();

    /**
     * @brief Destroys the mm_address_space object
     *
     */
    ~mm_address_space() override;
#endif
};

#define increment_vm_stat(as, name, amount) __sync_add_and_fetch(&as->name, amount)
#define decrement_vm_stat(as, name, amount) __sync_sub_and_fetch(&as->name, amount)

#endif
