/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/kunit.h>
#include <onyx/vm.h>

// Internal vm.cpp interfaces
struct vm_area_struct *vm_reserve_region(struct mm_address_space *as, unsigned long start,
                                         size_t size);
unsigned long vm_allocate_base(struct mm_address_space *as, unsigned long min, size_t size,
                               u64 flags);

TEST(mmap, test_range_at_end)
{
    // Test if an allocation cannot go overboard in the address space
    // i.e go over 0x00007fffffffffff, etc.
    constexpr unsigned long address_space_end = 0x7fffff;
    constexpr unsigned long second_region_try_start = 0x7e0000;
    constexpr unsigned long first_region_length = second_region_try_start - 0x1000;

    auto as = mm_address_space::create().unwrap();

    as->start = 0;
    as->end = address_space_end;

    assert(as->virtual_memory_size == 0);

    scoped_mutex g{as->vm_lock};

    auto region = vm_reserve_region(as.get(), 0x1000, first_region_length);
    ASSERT_NONNULL(region);

    increment_vm_stat(as, virtual_memory_size, first_region_length);

    auto allocated = vm_allocate_base(as.get(), second_region_try_start, 0x30000, VM_ADDRESS_USER);
    ASSERT_EQ(allocated, -1UL);
}

#ifdef __x86_64__

TEST(mmap, test_48_57_bit)
{
    constexpr unsigned long la48max = 0x00007fffffffffff;
    constexpr unsigned long la57max = 0x00ffffffffffffff;
    // Test if mmap CAN return a 57 bit address space,
    // and if it does not return it out of the blue.
    auto as = mm_address_space::create().unwrap();

    as->start = 0;
    as->end = la57max;
    scoped_mutex g{as->vm_lock};

    // 1) check if an allocation from under 48bit to over fails
    auto allocated = vm_allocate_base(as.get(), la48max - 0xfff, 0x2000, VM_ADDRESS_USER);
    EXPECT_EQ(allocated, -1UL);

    // 2) check if it succeeds with VM_FULL_ADDRESS_SPACE
    allocated = vm_allocate_base(as.get(), la48max - 0xfff, 0x2000,
                                 VM_ADDRESS_USER | VM_FULL_ADDRESS_SPACE);
    EXPECT_NE(allocated, -1UL);

    // 3) try grabbing a range up in the 57 bit space without FULL_ADDRESS_SPACE
    allocated = vm_allocate_base(as.get(), la48max + 1, 0x2000, VM_ADDRESS_USER);
    EXPECT_EQ(allocated, -1UL);

    // 4) and now with it
    allocated =
        vm_allocate_base(as.get(), la48max + 1, 0x2000, VM_ADDRESS_USER | VM_FULL_ADDRESS_SPACE);
    EXPECT_NE(allocated, -1UL);
}

#endif
