/*
 * Copyright (c) 2021 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstring>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <libonyx/handle.h>
#include <libonyx/process.h>
#include <libonyx/unique_fd.h>
#include <uapi/handle.h>
#include <uapi/mincore.h>
#include <uapi/process.h>

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

#ifdef __x86_64__
TEST(Vm, DISABLED_x86_64_LA57)
{
    // This does not work, because we can't detect LA57 from userspace easily, unless we want
    // to parse dmesg logs...

    void* ptr = mmap((void*) nullptr, page_size, PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
    ASSERT_NE(ptr, MAP_FAILED);
    // Check that mmap did not give us a pointer to 57-bit space
    ASSERT_LT((unsigned long) ptr, 0x00007fffffffffff);
    ptr =
        mmap((void*) (0x00007fffffffffff + 1), page_size, PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
    ASSERT_GT((unsigned long) ptr, 0x00007fffffffffff);
}
#endif

TEST(Vm, MprotectSplitMiddle)
{
    onx::unique_fd handle = onx_process_open(getpid(), ONX_HANDLE_CLOEXEC);
    ASSERT_TRUE(handle.valid());

    void* ptr = mmap(nullptr, page_size * 3, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    ASSERT_NE(ptr, MAP_FAILED);

    /* ptr + 0    | vma0
     * ptr + 4096 | vma0
     * ptr + 8192 | vma0
     */
    auto regions = get_mm_regions(handle.get());
    ASSERT_TRUE(
        address_is_mapped(regions, (unsigned long) ptr, page_size,
                          mapping_type{VM_REGION_PROT_READ | VM_REGION_PROT_WRITE, MAP_PRIVATE}));
    ASSERT_EQ(0, mprotect((void*) ((unsigned long) ptr + page_size), page_size, PROT_READ));
    regions = get_mm_regions(handle.get());

    /* ptr + 0    | vma0
     * ptr + 4096 | vma1
     * ptr + 8192 | vma2
     */
    auto region0 = get_mapping(regions, (unsigned long) ptr, page_size);
    auto region1 = get_mapping(regions, (unsigned long) ptr + page_size, page_size);
    auto region2 = get_mapping(regions, (unsigned long) ptr + (page_size * 2), page_size);
    ASSERT_NE(region0, nullptr);
    ASSERT_NE(region1, nullptr);
    ASSERT_NE(region2, nullptr);
    ASSERT_NE(region0, region1);
    ASSERT_NE(region0, region2);
    ASSERT_NE(region1, region2);
    ASSERT_EQ(region0->start + region0->length, (unsigned long) ptr + page_size);
    ASSERT_EQ(region0->protection, VM_REGION_PROT_READ | VM_REGION_PROT_WRITE);
    ASSERT_EQ(region1->start + region1->length, (unsigned long) ptr + (page_size * 2));
    ASSERT_EQ(region1->protection, VM_REGION_PROT_READ);
    ASSERT_EQ(region2->start, (unsigned long) ptr + (page_size * 2));
    ASSERT_EQ(region2->start + region2->length, (unsigned long) ptr + (page_size * 3));
    ASSERT_EQ(region2->protection, VM_REGION_PROT_READ | VM_REGION_PROT_WRITE);

    munmap(ptr, page_size * 3);
}

TEST(Vm, MunmapOverManyVmas)
{
    constexpr int npgs = 5;
    onx::unique_fd handle = onx_process_open(getpid(), ONX_HANDLE_CLOEXEC);
    ASSERT_TRUE(handle.valid());

    /* Test that a single munmap over many regions succeeds */
    void* ptr = mmap(nullptr, page_size * npgs, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    ASSERT_NE(ptr, MAP_FAILED);
    for (int i = 0; i < npgs; i++)
    {
        unsigned long addr = (unsigned long) ptr + (page_size * i);
        int perm = i & 1 ? PROT_EXEC | PROT_READ : PROT_WRITE | PROT_READ;
        ASSERT_EQ(mprotect((void*) addr, page_size, perm), 0);
        *(volatile char*) addr;
    }

    ASSERT_EQ(munmap(ptr, page_size * npgs), 0);

    auto regions = get_mm_regions(handle.get());
    for (int i = 0; i < npgs; i++)
    {
        unsigned long addr = (unsigned long) ptr + (page_size * i);
        ASSERT_FALSE(address_is_mapped(regions, addr, page_size));
    }
}

TEST(Vm, MprotectOverManyVmas)
{
    /* Test that a single mprotect over many regions succeeds */

    constexpr int npgs = 5;
    onx::unique_fd handle = onx_process_open(getpid(), ONX_HANDLE_CLOEXEC);
    ASSERT_TRUE(handle.valid());

    void* ptr = mmap(nullptr, page_size * npgs, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    ASSERT_NE(ptr, MAP_FAILED);
    for (int i = 0; i < npgs; i++)
    {
        unsigned long addr = (unsigned long) ptr + (page_size * i);
        int perm = i & 1 ? PROT_EXEC | PROT_READ : PROT_WRITE | PROT_READ;
        ASSERT_EQ(mprotect((void*) addr, page_size, perm), 0);
    }

    ASSERT_EQ(mprotect(ptr, page_size * npgs, PROT_NONE), 0);

    auto regions = get_mm_regions(handle.get());
    for (int i = 0; i < npgs; i++)
    {
        unsigned long addr = (unsigned long) ptr + (page_size * i);
        auto mapping = get_mapping(regions, addr, page_size);
        EXPECT_NE(mapping, nullptr);
        EXPECT_EQ(mapping->protection &
                      (VM_REGION_PROT_READ | VM_REGION_PROT_WRITE | VM_REGION_PROT_EXEC),
                  0);
    }

    ASSERT_EQ(munmap(ptr, page_size * npgs), 0);
}

TEST(Vm, MmapSharedFault)
{
    /* Simple test that tests MAP_SHARED faults */
    void* ptr = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    ASSERT_NE(ptr, MAP_FAILED);
    *(volatile unsigned char*) ptr;
    *(volatile unsigned char*) ptr = 10;
    ASSERT_EQ(munmap(ptr, page_size), 0);
}

static int mpagemap(void* addr, size_t length, uint64_t* pagemap)
{
    return syscall(SYS_mpagemap, addr, length, pagemap);
}

#define FLAG(flagname)      \
    {                       \
        flagname, #flagname \
    }

static struct
{
    uint64_t flag;
    const char* name;
} pagemap_flags[] = {
    FLAG(PAGE_PRESENT), FLAG(PAGE_GLOBAL),   FLAG(PAGE_WRITABLE), FLAG(PAGE_EXECUTABLE),
    FLAG(PAGE_DIRTY),   FLAG(PAGE_ACCESSED), FLAG(PAGE_USER),     FLAG(PAGE_HUGE),
};

static void dump_pte(uint64_t pte)
{
    printf("pte: %016lx", MAPPING_INFO_PADDR(pte));

    for (const auto& flag : pagemap_flags)
    {
        if (pte & flag.flag)
        {
            printf(" | %s", flag.name);
        }
    }

    printf("\n");
}

static void dump_ptes(uint64_t ptes[2])
{
    dump_pte(ptes[0]);
    dump_pte(ptes[1]);
}

TEST(Vm, MmapPrivateFileCow)
{
    /* TODO: In the future, mlock()ify this. This is currently not a problem, as we don't swap out
     * yet.
     */
    uint64_t oldval;
    uint64_t pages[2];
    onx::unique_fd fd = open("/bin/kernel_api_tests", O_RDWR);
    ASSERT_TRUE(fd.valid());

    volatile unsigned int* ptr0 = (volatile unsigned int*) mmap(
        (void*) nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd.get(), 0);
    ASSERT_NE(ptr0, MAP_FAILED);
    volatile unsigned int* ptr1 = (volatile unsigned int*) mmap(
        (void*) nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd.get(), 0);
    ASSERT_NE(ptr1, MAP_FAILED);

    /* Fault these pages in */
    *ptr0;
    *ptr1;
    /* Check if the PFNs are the same, and that it's read-only */
    ASSERT_NE(mpagemap((void*) ptr0, page_size, pages), -1);
    ASSERT_NE(mpagemap((void*) ptr1, page_size, &pages[1]), -1);

    if (pages[0] != pages[1])
        dump_ptes(pages);
    ASSERT_EQ(pages[0], pages[1]);
    EXPECT_FALSE(pages[0] & PAGE_WRITABLE);
    EXPECT_TRUE(pages[0] & PAGE_PRESENT);
    oldval = pages[1];

    /* Write to one. The other should keep its read-only value */
    *ptr0 = 10;
    ASSERT_NE(mpagemap((void*) ptr0, page_size, pages), -1);
    ASSERT_NE(mpagemap((void*) ptr1, page_size, &pages[1]), -1);
    EXPECT_NE(pages[0], pages[1]);
    EXPECT_TRUE(pages[0] & PAGE_WRITABLE);
    EXPECT_FALSE(pages[1] & PAGE_WRITABLE);
    EXPECT_EQ(MAPPING_INFO_PADDR(oldval), MAPPING_INFO_PADDR(pages[1]));

    /* Write to the other one. Both should be writable and have different pfns */
    *ptr1 = 11;
    ASSERT_NE(mpagemap((void*) ptr0, page_size, pages), -1);
    ASSERT_NE(mpagemap((void*) ptr1, page_size, &pages[1]), -1);
    EXPECT_NE(pages[0], pages[1]);
    EXPECT_TRUE(pages[0] & PAGE_WRITABLE);
    EXPECT_TRUE(pages[1] & PAGE_WRITABLE);
    EXPECT_NE(MAPPING_INFO_PADDR(oldval), MAPPING_INFO_PADDR(pages[1]));
    EXPECT_NE(MAPPING_INFO_PADDR(pages[0]), MAPPING_INFO_PADDR(pages[1]));

    munmap((void*) ptr0, page_size);
    munmap((void*) ptr1, page_size);
}

TEST(Vm, MmapPrivateAnonCow)
{
    /* TODO: In the future, mlock()ify this. This is currently not a problem, as we don't swap out
     * yet.
     */
    uint64_t oldval;
    uint64_t pages[2];

    volatile unsigned int* ptr0 = (volatile unsigned int*) mmap(
        (void*) nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    ASSERT_NE(ptr0, MAP_FAILED);
    volatile unsigned int* ptr1 = (volatile unsigned int*) mmap(
        (void*) nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    ASSERT_NE(ptr1, MAP_FAILED);

    /* Fault these pages in */
    *ptr0;
    *ptr1;
    /* Check if the PFNs are the same, and that it's read-only */
    ASSERT_NE(mpagemap((void*) ptr0, page_size, pages), -1);
    ASSERT_NE(mpagemap((void*) ptr1, page_size, &pages[1]), -1);

    if (pages[0] != pages[1])
        dump_ptes(pages);
    ASSERT_EQ(pages[0], pages[1]);
    EXPECT_FALSE(pages[0] & PAGE_WRITABLE);
    EXPECT_TRUE(pages[0] & PAGE_PRESENT);
    oldval = pages[1];

    /* Write to one. The other should keep its read-only value */
    *ptr0 = 10;
    ASSERT_NE(mpagemap((void*) ptr0, page_size, pages), -1);
    ASSERT_NE(mpagemap((void*) ptr1, page_size, &pages[1]), -1);
    EXPECT_NE(pages[0], pages[1]);
    EXPECT_TRUE(pages[0] & PAGE_WRITABLE);
    EXPECT_FALSE(pages[1] & PAGE_WRITABLE);
    EXPECT_EQ(MAPPING_INFO_PADDR(oldval), MAPPING_INFO_PADDR(pages[1]));

    /* Write to the other one. Both should be writable and have different pfns */
    *ptr1 = 11;
    ASSERT_NE(mpagemap((void*) ptr0, page_size, pages), -1);
    ASSERT_NE(mpagemap((void*) ptr1, page_size, &pages[1]), -1);
    EXPECT_NE(pages[0], pages[1]);
    EXPECT_TRUE(pages[0] & PAGE_WRITABLE);
    EXPECT_TRUE(pages[1] & PAGE_WRITABLE);
    EXPECT_NE(MAPPING_INFO_PADDR(oldval), MAPPING_INFO_PADDR(pages[1]));
    EXPECT_NE(MAPPING_INFO_PADDR(pages[0]), MAPPING_INFO_PADDR(pages[1]));

    munmap((void*) ptr0, page_size);
    munmap((void*) ptr1, page_size);
}

struct ipc_comm
{
    volatile int cmd;
    volatile uint64_t page;
    volatile unsigned int data;

    static ipc_comm* create();
    void wait_for(int cmd) const
    {
        while (this->cmd != cmd)
            __asm__ __volatile__("" ::: "memory");
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
    }
};

ipc_comm* ipc_comm::create()
{
    ipc_comm* commbuf = (ipc_comm*) mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                                         MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (commbuf == MAP_FAILED)
        return nullptr;
    return commbuf;
}

enum class anon_fork_state
{
    NONE = 0,
    CHILD0,
    PARENT0,
    CHILD1,
    PARENT1,
    CHILD2,
    PARENT2
};

TEST(Vm, MmapPrivateAnonForkCow)
{
    ipc_comm* buf = ipc_comm::create();
    ASSERT_NE(buf, nullptr);
    /* Make sure it's present in the page tables. Not that it shouldn't work if we don't do this,
     * but we're not testing MAP_SHARED at the moment.
     */
    buf->cmd = 0;

    volatile unsigned int* ptr0 = (volatile unsigned int*) mmap(
        (void*) nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

    /* Test if anon memory successfully cows and uncows itself after fork() */
    *ptr0 = 10;

    pid_t pid = fork();
    ASSERT_NE(pid, -1);

    if (pid == 0)
    {
        /* Retrieve ptr0's pagemap data */
        mpagemap((void*) ptr0, page_size, (uint64_t*) &buf->page);
        buf->data = *ptr0;
        buf->cmd = (int) anon_fork_state::CHILD0;
        buf->wait_for((int) anon_fork_state::PARENT0);
        /* Parent has uncowed themselves, do mpagemap again, and reload the value */
        mpagemap((void*) ptr0, page_size, (uint64_t*) &buf->page);
        buf->data = *ptr0;
        buf->cmd = (int) anon_fork_state::CHILD1;
        buf->wait_for((int) anon_fork_state::PARENT1);
        /* uncow ourselves */
        *ptr0 = 0xb00;
        mpagemap((void*) ptr0, page_size, (uint64_t*) &buf->page);
        buf->data = *ptr0;
        buf->cmd = (int) anon_fork_state::CHILD2;
        buf->wait_for((int) anon_fork_state::PARENT2);
        _exit(0);
    }
    else
    {
        uint64_t tmp, tmp2;
        /* Parent. Here we actually test things */
        buf->wait_for((int) anon_fork_state::CHILD0);

        /* Check the CoW state */
        mpagemap((void*) ptr0, page_size, &tmp);
        if (buf->page & PAGE_PRESENT)
        {
            EXPECT_EQ(MAPPING_INFO_PADDR(buf->page), MAPPING_INFO_PADDR(tmp));
            EXPECT_FALSE(buf->page & PAGE_WRITABLE);
        }

        EXPECT_FALSE(tmp & PAGE_WRITABLE);
        EXPECT_EQ(*ptr0, 10);
        EXPECT_EQ(buf->data, 10);

        /* now un-CoW the parent's page */
        *ptr0 = 0xbeef;
        mpagemap((void*) ptr0, page_size, &tmp2);
        EXPECT_NE(tmp, tmp2);
        EXPECT_TRUE(tmp2 & PAGE_WRITABLE);
        EXPECT_NE(MAPPING_INFO_PADDR(tmp), MAPPING_INFO_PADDR(tmp2));

        /* Tmp now has the current pagemap, tmp2 has the old child's pagemap */
        tmp = tmp2;
        tmp2 = buf->page;
        buf->cmd = (int) anon_fork_state::PARENT0;
        buf->wait_for((int) anon_fork_state::CHILD1);
        ASSERT_TRUE(buf->page & PAGE_PRESENT);
        EXPECT_FALSE(buf->page & PAGE_WRITABLE);
        EXPECT_NE(MAPPING_INFO_PADDR(tmp), MAPPING_INFO_PADDR(buf->page));
        EXPECT_EQ(buf->data, 10);
        EXPECT_EQ(*ptr0, 0xbeef);

        buf->cmd = (int) anon_fork_state::PARENT1;
        /* The child will now uncow itself */
        buf->wait_for((int) anon_fork_state::CHILD2);
        ASSERT_TRUE(buf->page & PAGE_PRESENT);
        EXPECT_TRUE(buf->page & PAGE_WRITABLE);
        EXPECT_NE(MAPPING_INFO_PADDR(tmp), MAPPING_INFO_PADDR(buf->page));
        EXPECT_EQ(buf->data, 0xb00);
        EXPECT_EQ(*ptr0, 0xbeef);
        buf->cmd = (int) anon_fork_state::PARENT2;
    }
}
