/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstring>
#include <string>
#include <vector>

#include <onyx/public/handle.h>
#include <onyx/public/process.h>

#include <gtest/gtest.h>
#include <libonyx/process.h>
#include <libonyx/unique_fd.h>

class mapping_type
{
    std::optional<unsigned long> perms_;
    std::optional<unsigned long> type_;

public:
    mapping_type() = default;
    mapping_type(unsigned long perms, unsigned long type) : perms_{perms}, type_{type}
    {
    }

    unsigned long perms() const
    {
        return perms_.value();
    }

    unsigned long type() const
    {
        return type_.value();
    }

    bool has_values() const
    {
        return perms_.has_value() && type_.has_value();
    }
};

static bool memory_map_is_valid(const std::vector<onx::vm_region>& regions)
{
    // Check for overlaps
    for (size_t i = 1; i < regions.size(); i++)
    {
        if (regions[i - 1].start + regions[i - 1].length >= regions[i].start)
            return true;
    }

    return false;
}

static bool address_is_mapped(const std::vector<onx::vm_region>& regions, unsigned long address,
                              size_t length, mapping_type type = {})
{
    for (const auto& reg : regions)
    {
        if ((reg.start <= address && reg.start + reg.length >= address + length) ||
            (address > reg.start && reg.start + reg.length > address))
        {
            if (type.has_values())
            {
                return type.type() == reg.mapping_type &&
                       (reg.protection & type.perms()) == type.perms();
            }

            return true;
        }
    }

    return false;
}

static const onx::vm_region* get_mapping(const std::vector<onx::vm_region>& regions,
                                         unsigned long address, size_t length)
{
    for (const auto& reg : regions)
    {
        if ((reg.start <= address && reg.start + reg.length >= address + length) ||
            (address > reg.start && reg.start + reg.length > address))
        {
            return &reg;
        }
    }

    return nullptr;
}

static std::pair<unsigned long, size_t> regions_find_gap(const std::vector<onx::vm_region>& regions,
                                                         size_t length)
{
    // Lets assume some safe 64 bit mins and maxes
    unsigned long min = 0x200000;
    unsigned long max = 0x8000000000000000;
    unsigned long last = min;

    // These regions are already sorted.
    for (const auto& reg : regions)
    {
        if (reg.start - last >= length)
            return std::pair{min, length};
        last = reg.start + reg.length;
    }

    if (max - last >= length)
        return std::pair{last, length};
    throw std::runtime_error("No gap found in the memory map");
}

TEST(Vm, MmapMunmapWorks)
{
    onx::unique_fd handle = onx_process_open(getpid(), ONX_HANDLE_CLOEXEC);
    ASSERT_TRUE(handle.valid());
    auto regions = onx::get_mm_regions(handle.get());
    void* ptr =
        mmap(nullptr, 4096UL * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

    ASSERT_NE(ptr, MAP_FAILED);

    auto regions2 = onx::get_mm_regions(handle.get());

    ASSERT_FALSE(address_is_mapped(regions, (unsigned long) ptr, 4096UL * 4));
    ASSERT_TRUE(address_is_mapped(regions2, (unsigned long) ptr, 4096UL * 4,
                                  {VM_REGION_PROT_READ | VM_REGION_PROT_WRITE, MAP_PRIVATE}));
    ASSERT_TRUE(memory_map_is_valid(regions2));
    auto st = munmap(ptr, 4096 * 4UL);
    ASSERT_NE(st, -1);
    auto regions3 = onx::get_mm_regions(handle.get());

    ASSERT_FALSE(address_is_mapped(regions3, (unsigned long) ptr, 4096UL * 4));
    ASSERT_TRUE(memory_map_is_valid(regions3));
}

TEST(Vm, MmapFixedWorks)
{
    onx::unique_fd handle = onx_process_open(getpid(), ONX_HANDLE_CLOEXEC);
    ASSERT_TRUE(handle.valid());
    auto regions = onx::get_mm_regions(handle.get());

    const auto [addr, length] = regions_find_gap(regions, 4096);

    void* ptr = mmap((void*) addr, length, PROT_READ | PROT_WRITE,
                     MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

    ASSERT_NE(ptr, MAP_FAILED);
    ASSERT_EQ((unsigned long) ptr, addr);

    auto regions2 = onx::get_mm_regions(handle.get());

    ASSERT_FALSE(address_is_mapped(regions, (unsigned long) ptr, length));
    ASSERT_TRUE(address_is_mapped(regions2, (unsigned long) ptr, length,
                                  {VM_REGION_PROT_READ | VM_REGION_PROT_WRITE, MAP_PRIVATE}));

    auto st = munmap(ptr, length);
    ASSERT_NE(st, -1);
    auto regions3 = onx::get_mm_regions(handle.get());

    ASSERT_FALSE(address_is_mapped(regions3, (unsigned long) ptr, length));
}

TEST(Vm, MmapFixedOverwrites)
{
    onx::unique_fd handle = onx_process_open(getpid(), ONX_HANDLE_CLOEXEC);
    ASSERT_TRUE(handle.valid());

    size_t length = 4096UL * 4;

    void* ptr = mmap(nullptr, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

    ASSERT_NE(ptr, MAP_FAILED);

    auto ptr2 = mmap((void*) ((unsigned long) ptr + 4096), 4096, PROT_WRITE,
                     MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

    ASSERT_EQ((unsigned long) ptr2, (unsigned long) ptr + 4096);

    auto regions2 = onx::get_mm_regions(handle.get());

    ASSERT_TRUE(address_is_mapped(regions2, (unsigned long) ptr, 4096, {0, MAP_PRIVATE}));
    ASSERT_TRUE(address_is_mapped(regions2, (unsigned long) ptr2, 4096,
                                  {VM_REGION_PROT_WRITE, MAP_PRIVATE}));
    ASSERT_TRUE(address_is_mapped(regions2, (unsigned long) ptr2 + 4096, length - 4096 * 2,
                                  {0, MAP_PRIVATE}));
    ASSERT_TRUE(memory_map_is_valid(regions2));

    auto st = munmap(ptr, length);
    ASSERT_NE(st, -1);
    auto regions3 = onx::get_mm_regions(handle.get());

    ASSERT_FALSE(address_is_mapped(regions3, (unsigned long) ptr, length));
    ASSERT_TRUE(memory_map_is_valid(regions3));
}

TEST(Vm, MunmapSplitsProperly)
{
    onx::unique_fd handle = onx_process_open(getpid(), ONX_HANDLE_CLOEXEC);
    ASSERT_TRUE(handle.valid());

    onx::unique_fd fd = open("/bin/kernel_api_tests", O_RDONLY);
    ASSERT_TRUE(fd.valid());

    void* ptr = mmap((void*) nullptr, 4096UL * 3, PROT_READ, MAP_SHARED, fd.get(), 0);
    ASSERT_NE(ptr, MAP_FAILED);

    auto st = munmap((void*) ((unsigned long) ptr + 4096), 4096);
    ASSERT_NE(st, -1);

    auto regions = onx::get_mm_regions(handle.get());

    ASSERT_TRUE(address_is_mapped(regions, (unsigned long) ptr, 4096));
    auto first_mapping = get_mapping(regions, (unsigned long) ptr, 4096);
    ASSERT_NE(first_mapping, nullptr);
    auto second_mapping = get_mapping(regions, (unsigned long) ptr + (4096 * 2), 4096);
    ASSERT_NE(second_mapping, nullptr);
    EXPECT_EQ((void*) second_mapping->start, (void*) ((unsigned long) ptr + 4096 * 2));
    EXPECT_EQ(second_mapping->offset, 4096UL * 2);
    EXPECT_EQ(second_mapping->protection, first_mapping->protection);
    ASSERT_NE(munmap((void*) ptr, 4096UL * 3), -1);

    auto regions2 = onx::get_mm_regions(handle.get());

    ASSERT_FALSE(address_is_mapped(regions2, (unsigned long) ptr, 4096UL * 3));
    ASSERT_TRUE(memory_map_is_valid(regions2));
}
