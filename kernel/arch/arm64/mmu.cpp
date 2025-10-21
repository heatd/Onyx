/*
 * Copyright (c) 2022 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#include <onyx/arm64/mmu.h>
#include <onyx/cpu.h>
#include <onyx/intrinsics.h>
#include <onyx/page.h>
#include <onyx/paging.h>
#include <onyx/panic.h>
#include <onyx/pgtable.h>
#include <onyx/process.h>
#include <onyx/serial.h>
#include <onyx/smp.h>
#include <onyx/vm.h>

static char buffer[1000];

#define budget_printk(...)                         \
    snprintf(buffer, sizeof(buffer), __VA_ARGS__); \
    platform_serial_write(buffer, strlen(buffer))

extern "C"
{
int pgd_shift = 39, p4d_ptrs = 1;
unsigned int arm64_paging_levels = 4;
}

static const unsigned int arm64_max_paging_levels = 5;
#define ARM64_MMU_PERM_MASK 0xfff8000000000ffful

// Page table entries have the top bits reserved (63 - 51) and the lower 12 bits
// clang format note: it's misformatting the macro
// clang-format off
#define PML_EXTRACT_ADDRESS(n) ((n) & ~ARM64_MMU_PERM_MASK)
#define PML_EXTRACT_PERMS(n) ((n) & ARM64_MMU_PERM_MASK)
// clang-format on

static inline void __native_tlb_invalidate_page(void *addr)
{
    // TODO: ASIDs
    __asm__ __volatile__("tlbi vaae1is, %0" ::"r"((unsigned long) addr >> PAGE_SHIFT));
    dsb();
}

static bool pte_empty(uint64_t pte)
{
    return pte == 0;
}

PML *alloc_pt()
{
    struct page *p = alloc_page(0);

    return p != nullptr ? (PML *) pfn_to_paddr(page_to_pfn(p)) : nullptr;
}

PML *boot_pt;

PML *get_current_page_tables()
{
    struct process *p = get_current_process();
    if (!p)
        return boot_pt;
    return (PML *) p->address_space->arch_mmu.top_pt;
}

#define HUGE1GB_SHIFT  30
#define HUGE1GB_SIZE   0x40000000
#define LARGE2MB_SHIFT 21
#define LARGE2MB_SIZE  0x200000

static void addr_to_indices(unsigned long virt, unsigned int *indices)
{
    for (unsigned int i = 0; i < arm64_paging_levels; i++)
    {
        indices[i] = (virt >> 12) >> (i * 9) & 0x1ff;
    }
}

static bool pt_entry_is_huge(unsigned long pt_entry)
{
    return !(pt_entry & ARM64_MMU_TABLE);
}

void *__virtual2phys(PML *__pml, void *ptr)
{
    unsigned long virt = (unsigned long) ptr;
    unsigned int indices[arm64_max_paging_levels];

    addr_to_indices(virt, indices);

    PML *pml = (PML *) ((uint64_t) __pml + PHYS_BASE);

    for (unsigned int i = arm64_paging_levels; i != 1; i--)
    {
        uint64_t entry = pml->entries[indices[i - 1]];

        if (!(entry & ARM64_MMU_VALID))
            return (void *) -1;

        if (pt_entry_is_huge(entry))
        {
            /* Is huge page, check if it's a 1gb or 2mb */
            /* 1GB pages reside in PML3, 2MB pages reside in PML2 */
            bool is_1gb = i == 3;
            unsigned long size = is_1gb ? HUGE1GB_SIZE : LARGE2MB_SIZE;
            unsigned long page_base = PML_EXTRACT_ADDRESS(entry);
            unsigned long page_off = virt & (size - 1);
            return (void *) (page_base + page_off);
        }

        pml = (PML *) PHYS_TO_VIRT(PML_EXTRACT_ADDRESS(entry));
    }

    unsigned long phys = PML_EXTRACT_ADDRESS(pml->entries[indices[0]]);
    unsigned long page_off = virt & (PAGE_SIZE - 1);

    return (void *) (phys + page_off);
}

void *virtual2phys(void *ptr)
{
    return __virtual2phys(get_current_page_tables(), ptr);
}

unsigned long placement_mappings_start = 0xffffffffffc00000;

#define EARLY_BOOT_GDB_DELAY              \
    volatile int __gdb_debug_counter = 0; \
    while (__gdb_debug_counter != 1)

void __native_tlb_invalidate_all()
{
    __asm__ __volatile__("tlbi vmalle1is");
}

PML *arm64_get_kernel_page_table()
{
    return (PML *) mrs(REG_TTBR1);
}

PML phys_map_pt __attribute__((aligned(PAGE_SIZE)));

void paging_init()
{
    /* Get the current PML and store it */
    boot_pt = (PML *) arm64_get_kernel_page_table();
    /* Bootstrap the first 1GB */
    uintptr_t virt = PHYS_BASE;

    unsigned int indices[arm64_max_paging_levels];

    addr_to_indices(virt, indices);

    // Create two mappings of 512GB(1TB)
    auto page_table_flags = ARM64_MMU_INNER_SHAREABLE | ARM64_MMU_TABLE | ARM64_MMU_VALID |
                            ARM64_MMU_AF | MMU_PTR_ATTR_NORMAL_MEMORY;
    unsigned long page_table =
        ((unsigned long) &phys_map_pt) - KERNEL_VIRTUAL_BASE + get_kernel_phys_offset();
    boot_pt->entries[indices[arm64_paging_levels - 1]] = page_table | page_table_flags;

    for (unsigned long i = 0; i < 512; i++)
    {
        phys_map_pt.entries[i] = (i << HUGE1GB_SHIFT) | ARM64_MMU_INNER_SHAREABLE |
                                 ARM64_MMU_BLOCK | ARM64_MMU_VALID | ARM64_MMU_AF |
                                 MMU_PTR_ATTR_NORMAL_MEMORY;
    }
}

/**
 * @brief Clone the architecture specific part of an address space
 *
 * @param addr_space The new address space
 * @param original The original address space
 * @return 0 on success, negative error codes
 */
int paging_clone_as(mm_address_space *addr_space, mm_address_space *original)
{
    PML *new_pml = alloc_pt();
    if (!new_pml)
        return -ENOMEM;

    addr_space->page_tables_size = PAGE_SIZE;

    addr_space->arch_mmu.top_pt = new_pml;
    return 0;
}

void paging_load_el0_pt(PML *pml)
{
    msr("ttbr0_el1", pml);
    isb();
    dsb();
    __native_tlb_invalidate_all();
}

void paging_load_top_pt(PML *pml)
{
    msr("ttbr1_el1", pml);
    isb();
    dsb();
    __native_tlb_invalidate_all();
}

int is_invalid_arch_range(void *address, size_t pages)
{
    unsigned long addr = (unsigned long) address;
    auto limit = addr + (pages << PAGE_SHIFT);

    if (addr <= arch_low_half_max && limit >= VM_HIGHER_HALF)
        return -1;
    return 0;
}

extern char _text_start;
extern char _text_end;
extern char _data_start;
extern char _data_end;
extern char _vdso_sect_start;
extern char _vdso_sect_end;
extern char VIRT_BASE;

void arm64_dump_pt(PML *pml, unsigned int level)
{
    for (unsigned int i = 0; i < 512; i++)
    {
        auto entry = pml->entries[i];
        if (!(entry & ARM64_MMU_VALID))
            continue;
        bool is_block = !(entry & ARM64_MMU_TABLE);
        PML *next_pml = (PML *) PHYS_TO_VIRT(PML_EXTRACT_ADDRESS(entry));
        if (!is_block)
        {
            budget_printk("Level %u [%03u]: entry %016lx %016lx\n", level, i, entry,
                          (unsigned long) next_pml);
        }
        else
        {
            budget_printk("Level %u [%03u]: entry %016lx BLOCK %016lx\n", level, i, entry,
                          PML_EXTRACT_ADDRESS(entry));
        }

        if (level != 0 && !is_block)
            arm64_dump_pt(next_pml, level - 1);
    }
}

void arm64_dump_mmu(PML *pml)
{
    arm64_dump_pt(pml, 3);
}

void paging_protect_kernel()
{
    PML *original_pml = boot_pt;
    PML *pml = alloc_pt();
    assert(pml != nullptr);
    boot_pt = pml;

    uintptr_t text_start = (uintptr_t) &_text_start;
    uintptr_t data_start = (uintptr_t) &_data_start;
    uintptr_t vdso_start = (uintptr_t) &_vdso_sect_start;

    memcpy((PML *) ((uintptr_t) pml + PHYS_BASE), (PML *) ((uintptr_t) original_pml + PHYS_BASE),
           sizeof(PML));
    PML *p = (PML *) ((uintptr_t) pml + PHYS_BASE);
    p->entries[511] = 0UL;

    kernel_address_space.arch_mmu.top_pt = pml;

    size_t size = (uintptr_t) &_text_end - text_start;
    map_pages_to_vaddr((void *) text_start,
                       (void *) (text_start - KERNEL_VIRTUAL_BASE + get_kernel_phys_offset()), size,
                       VM_EXEC);

    size = (uintptr_t) &_data_end - data_start;
    map_pages_to_vaddr((void *) data_start,
                       (void *) (data_start - KERNEL_VIRTUAL_BASE + get_kernel_phys_offset()), size,
                       VM_READ | VM_WRITE);

    size = (uintptr_t) &_vdso_sect_end - vdso_start;
    map_pages_to_vaddr((void *) vdso_start,
                       (void *) (vdso_start - KERNEL_VIRTUAL_BASE + get_kernel_phys_offset()), size,
                       VM_READ | VM_WRITE);
    percpu_map_master_copy();

    paging_load_top_pt(pml);
}

unsigned long total_shootdowns = 0;

void paging_invalidate(void *page, size_t pages)
{
    uintptr_t p = (uintptr_t) page;

    if (pages > 128)
    {
        __native_tlb_invalidate_all();
        return;
    }

    for (size_t i = 0; i < pages; i++, p += PAGE_SIZE)
    {
        total_shootdowns++;
        __native_tlb_invalidate_page((void *) p);
    }
}

void paging_free_pml2(PML *pml)
{
    for (unsigned long entry : pml->entries)
    {
        if (entry & ARM64_MMU_VALID && !(pt_entry_is_huge(entry)))
        {
            /* We don't need to free pages since these functions
             * are supposed to only tear down paging tables */
            unsigned long phys_addr = PML_EXTRACT_ADDRESS(entry);

            free_page(phys_to_page(phys_addr));
        }
    }
}

void paging_free_pml3(PML *pml)
{
    for (auto entry : pml->entries)
    {
        if (entry & ARM64_MMU_VALID)
        {
            unsigned long phys_addr = PML_EXTRACT_ADDRESS(entry);
            PML *pml2 = (PML *) PHYS_TO_VIRT(phys_addr);
            paging_free_pml2(pml2);

            free_page(phys_to_page(phys_addr));
        }
    }
}

void paging_free_page_tables(struct mm_address_space *mm)
{
    PML *pml = (PML *) PHYS_TO_VIRT(mm->arch_mmu.top_pt);

    for (int i = 0; i < 256; i++)
    {
        if (pml->entries[i] & ARM64_MMU_VALID)
        {
            unsigned long phys_addr = PML_EXTRACT_ADDRESS(pml->entries[i]);
            PML *pml3 = (PML *) PHYS_TO_VIRT(phys_addr);
            paging_free_pml3(pml3);

            free_page(phys_to_page(phys_addr));
            pml->entries[i] = 0;
        }
    }

    free_page(phys_to_page((unsigned long) mm->arch_mmu.top_pt));
}

/**
 * @brief Free the architecture dependent parts of the address space.
 * Called on address space destruction.
 *
 * @param mm The to-be-destroyed address space.
 */
void vm_free_arch_mmu(struct arch_mm_address_space *mm)
{
    free_page(phys_to_page((unsigned long) mm->top_pt));
}

/**
 * @brief Loads a new address space.
 *
 * @param mm The to-be-loaded address space.
 */
void vm_load_arch_mmu(struct arch_mm_address_space *mm)
{
    paging_load_el0_pt((PML *) mm->top_pt);
}

/**
 * @brief Saves the current address space in \p mm
 *
 * @param mm A pointer to a valid mm_address_space.
 */
void vm_save_current_mmu(struct mm_address_space *mm)
{
    mm->arch_mmu.top_pt = get_current_page_tables();
}

static inline bool is_higher_half(unsigned long address)
{
    return address >= VM_HIGHER_HALF;
}

PER_CPU_VAR(unsigned long tlb_nr_invals) = 0;
PER_CPU_VAR(unsigned long nr_tlb_shootdowns) = 0;

struct mm_shootdown_info
{
    unsigned long addr;
    size_t pages;
    mm_address_space *mm;
};

void arm64_invalidate_tlb(void *context)
{
    auto info = (mm_shootdown_info *) context;
    auto addr = info->addr;
    auto pages = info->pages;
    auto addr_space = info->mm;

    auto curr_thread = get_current_thread();

    if (is_higher_half(addr) ||
        (curr_thread->owner && curr_thread->owner->get_aspace() == addr_space))
    {
        paging_invalidate((void *) addr, pages);
        add_per_cpu(tlb_nr_invals, 1);
    }
}

/**
 * @brief Invalidates a memory range.
 *
 * @param addr The start of the memory range.
 * @param pages The size of the memory range, in pages.
 * @param mm The target address space.
 */
void mmu_invalidate_range(unsigned long addr, size_t pages, mm_address_space *mm)
{
    add_per_cpu(nr_tlb_shootdowns, 1);
    mm_shootdown_info info{addr, pages, mm};

    auto our_cpu = get_cpu_nr();
    cpumask mask;

    if (addr >= VM_HIGHER_HALF)
    {
        mask = cpumask::all_but_one(our_cpu);
    }
    else
    {
        mask = mm->active_mask;
        mask.remove_cpu(our_cpu);
    }

    smp::sync_call_with_local(arm64_invalidate_tlb, &info, mask, arm64_invalidate_tlb, &info);
}

/**
 * @brief Verifies the address space's accounting (RSS, PT Size)
 *
 * @param as The address space to verify.
 */
void mmu_verify_address_space_accounting(mm_address_space *as)
{
}

/**
 * @brief Invalidate the TLB after upgrading PTE protection
 * Invalidates the TLB when upgrading PTE permissions. It isn't required to sync this invalidation
 * with other cores.
 * @param mm Address space
 * @param virt Virtual address to invalidate
 */
void tlbi_upgrade_pte_prots(struct mm_address_space *mm, unsigned long virt)
{
    /* Dodge the IPIs and just paging_invalidate */
    paging_invalidate((void *) virt, 1);
    add_per_cpu(tlb_nr_invals, 1);
}

/**
 * @brief Handle a seemingly spurious fault locally
 * Make sure we sync the TLB when we find a spurious fault.
 * @param mm Address space
 * @param virt Virtual address to invalidate
 */
void tlbi_handle_spurious_fault_pte(struct mm_address_space *mm, unsigned long virt)
{
    paging_invalidate((void *) virt, 1);
    add_per_cpu(tlb_nr_invals, 1);
}
