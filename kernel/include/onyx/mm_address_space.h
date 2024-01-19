/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_MM_ADDRESS_SPACE_H
#define _ONYX_MM_ADDRESS_SPACE_H

#include <onyx/refcount.h>

#include <platform/vm.h>

/**
 * @brief An mm_address_space represents an address space inside the kernel and stores
 * all kinds of relevant data on it, like the owner process, a tree of vm_area_structs, locks
 * various statistics, etc.
 *
 */
struct mm_address_space : public refcountable
{
    /* Virtual address space WAVL tree */
    struct bst_root region_tree;
    unsigned long start{};
    unsigned long end{};
    mutex vm_lock{};

    /* mmap(2) base */
    void *mmap_base{};

    /* Process' brk */
    void *brk{};

    size_t virtual_memory_size{};
    size_t resident_set_size{};
    size_t shared_set_size{};
    size_t page_faults{};
    size_t page_tables_size{};

    arch_mm_address_space arch_mmu{};

    // The active mask keeps track of where the address space is running.
    // This serves as an optimisation when doing a TLB shootdown, as it lets us
    // limit the shootdowns to CPUs where the address space is active instead of every CPU.
    cpumask active_mask{};

    spinlock page_table_lock{};

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
        bst_root_initialize(&region_tree);
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
};

#define increment_vm_stat(as, name, amount) __sync_add_and_fetch(&as->name, amount)
#define decrement_vm_stat(as, name, amount) __sync_sub_and_fetch(&as->name, amount)

#endif
