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
#include <libonyx/handle.h>
#include <libonyx/process.h>
#include <libonyx/unique_fd.h>

static unsigned long page_size = sysconf(_SC_PAGESIZE);

struct vm_tests_vm_region_info
{
    std::array<onx_process_vm_region, 256> array;
    size_t nr;
};

// We roll our own get_mm_regions because we cannot allocate in the middle of these tests

vm_tests_vm_region_info get_mm_regions(int handle)
{
    char data[sizeof(onx_process_vm_region) * 256];
    vm_tests_vm_region_info info;
    size_t quantity;
    auto status = onx_handle_query(handle, data, 256 * sizeof(onx_process_vm_region),
                                   PROCESS_GET_VM_REGIONS, &quantity, nullptr);
    if (status == -1)
        throw std::system_error(errno, std::generic_category());

    size_t idx = 0;
    for (size_t i = 0; i < quantity;)
    {
        const onx_process_vm_region* reg = (const onx_process_vm_region*) &data[i];
        i += reg->size;
        info.array[idx++] = *reg;
    }

    info.nr = idx;
    return info;
}

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

static bool memory_map_is_valid(const vm_tests_vm_region_info& regions)
{
    // Check for overlaps
    for (size_t i = 1; i < regions.nr; i++)
    {
        if (regions.array[i - 1].start + regions.array[i - 1].length >= regions.array[i].start)
            return true;
    }

    return false;
}

static bool address_is_mapped(const vm_tests_vm_region_info& regions, unsigned long address,
                              size_t length, mapping_type type = {})
{
    for (size_t i = 0; i < regions.nr; i++)
    {
        const auto& reg = regions.array[i];
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

static const onx_process_vm_region* get_mapping(const vm_tests_vm_region_info& regions,
                                                unsigned long address, size_t length)
{
    for (size_t i = 0; i < regions.nr; i++)
    {
        const auto& reg = regions.array[i];
        if ((reg.start <= address && reg.start + reg.length >= address + length) ||
            (address > reg.start && reg.start + reg.length > address))
        {
            return &reg;
        }
    }

    return nullptr;
}

static std::pair<unsigned long, size_t> regions_find_gap(const vm_tests_vm_region_info& regions,
                                                         size_t length)
{
    // Lets assume some safe 64 bit mins and maxes
    unsigned long min = 0x200000;
    unsigned long max = 0x8000000000000000;
    unsigned long last = min;

    // These regions are already sorted.
    for (size_t i = 0; i < regions.nr; i++)
    {
        const auto& reg = regions.array[i];
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
    auto regions = get_mm_regions(handle.get());
    void* ptr =
        mmap(nullptr, page_size * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

    ASSERT_NE(ptr, MAP_FAILED);

    auto regions2 = get_mm_regions(handle.get());

    ASSERT_FALSE(address_is_mapped(regions, (unsigned long) ptr, page_size * 4));
    ASSERT_TRUE(address_is_mapped(regions2, (unsigned long) ptr, page_size * 4,
                                  {VM_REGION_PROT_READ | VM_REGION_PROT_WRITE, MAP_PRIVATE}));
    ASSERT_TRUE(memory_map_is_valid(regions2));
    auto st = munmap(ptr, page_size * 4UL);
    ASSERT_NE(st, -1);
    auto regions3 = get_mm_regions(handle.get());

    ASSERT_FALSE(address_is_mapped(regions3, (unsigned long) ptr, page_size * 4));
    ASSERT_TRUE(memory_map_is_valid(regions3));
}

TEST(Vm, MmapFixedWorks)
{
    onx::unique_fd handle = onx_process_open(getpid(), ONX_HANDLE_CLOEXEC);
    ASSERT_TRUE(handle.valid());
    auto regions = get_mm_regions(handle.get());

    const auto [addr, length] = regions_find_gap(regions, page_size);

    void* ptr = mmap((void*) addr, length, PROT_READ | PROT_WRITE,
                     MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

    ASSERT_NE(ptr, MAP_FAILED);
    ASSERT_EQ((unsigned long) ptr, addr);

    auto regions2 = get_mm_regions(handle.get());

    ASSERT_FALSE(address_is_mapped(regions, (unsigned long) ptr, length));
    ASSERT_TRUE(address_is_mapped(regions2, (unsigned long) ptr, length,
                                  {VM_REGION_PROT_READ | VM_REGION_PROT_WRITE, MAP_PRIVATE}));

    auto st = munmap(ptr, length);
    ASSERT_NE(st, -1);
    auto regions3 = get_mm_regions(handle.get());

    ASSERT_FALSE(address_is_mapped(regions3, (unsigned long) ptr, length));
}

TEST(Vm, MmapFixedOverwrites)
{
    onx::unique_fd handle = onx_process_open(getpid(), ONX_HANDLE_CLOEXEC);
    ASSERT_TRUE(handle.valid());

    size_t length = page_size * 4;

    void* ptr = mmap(nullptr, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

    ASSERT_NE(ptr, MAP_FAILED);

    auto ptr2 = mmap((void*) ((unsigned long) ptr + page_size), page_size, PROT_WRITE,
                     MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

    ASSERT_EQ((unsigned long) ptr2, (unsigned long) ptr + page_size);

    auto regions2 = get_mm_regions(handle.get());

    ASSERT_TRUE(address_is_mapped(regions2, (unsigned long) ptr, page_size, {0, MAP_PRIVATE}));
    ASSERT_TRUE(address_is_mapped(regions2, (unsigned long) ptr2, page_size,
                                  {VM_REGION_PROT_WRITE, MAP_PRIVATE}));
    ASSERT_TRUE(address_is_mapped(regions2, (unsigned long) ptr2 + page_size,
                                  length - page_size * 2, {0, MAP_PRIVATE}));
    ASSERT_TRUE(memory_map_is_valid(regions2));

    auto st = munmap(ptr, length);
    ASSERT_NE(st, -1);
    auto regions3 = get_mm_regions(handle.get());

    ASSERT_FALSE(address_is_mapped(regions3, (unsigned long) ptr, length));
    ASSERT_TRUE(memory_map_is_valid(regions3));
}

TEST(Vm, MunmapSplitsProperly)
{
    onx::unique_fd handle = onx_process_open(getpid(), ONX_HANDLE_CLOEXEC);
    ASSERT_TRUE(handle.valid());

    onx::unique_fd fd = open("/bin/kernel_api_tests", O_RDONLY);
    ASSERT_TRUE(fd.valid());

    void* ptr = mmap((void*) nullptr, page_size * 3, PROT_READ, MAP_SHARED, fd.get(), 0);
    ASSERT_NE(ptr, MAP_FAILED);

    auto st = munmap((void*) ((unsigned long) ptr + page_size), page_size);
    ASSERT_NE(st, -1);

    auto regions = get_mm_regions(handle.get());

    ASSERT_TRUE(address_is_mapped(regions, (unsigned long) ptr, page_size));
    auto first_mapping = get_mapping(regions, (unsigned long) ptr, page_size);
    ASSERT_NE(first_mapping, nullptr);
    auto second_mapping = get_mapping(regions, (unsigned long) ptr + (page_size * 2), page_size);
    ASSERT_NE(second_mapping, nullptr);
    EXPECT_EQ((void*) second_mapping->start, (void*) ((unsigned long) ptr + page_size * 2));
    EXPECT_EQ(second_mapping->offset, page_size * 2);
    EXPECT_EQ(second_mapping->protection, first_mapping->protection);
    ASSERT_NE(munmap((void*) ptr, page_size * 3), -1);

    auto regions2 = get_mm_regions(handle.get());

    ASSERT_FALSE(address_is_mapped(regions2, (unsigned long) ptr, page_size * 3));
    ASSERT_TRUE(memory_map_is_valid(regions2));
}
