/*
 * Copyright (c) 2022 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#include <onyx/cpu.h>
#include <onyx/page.h>
#include <onyx/paging.h>
#include <onyx/panic.h>
#include <onyx/process.h>
#include <onyx/riscv/intrinsics.h>
#include <onyx/smp.h>
#include <onyx/vm.h>

#define RISCV_SATP_4LEVEL_MMU (9UL << 60)

static const unsigned int riscv_paging_levels = 4;
static const unsigned int riscv_max_paging_levels = 5;

#define PML_EXTRACT_ADDRESS(n) ((n >> 10) << 12)
#define RISCV_MMU_VALID        (1 << 0)
#define RISCV_MMU_READ         (1 << 1)
#define RISCV_MMU_WRITE        (1 << 2)
#define RISCV_MMU_EXECUTE      (1 << 3)
#define RISCV_MMU_USER         (1 << 4)
#define RISCV_MMU_GLOBAL       (1 << 5)
#define RISCV_MMU_ACCESSED     (1 << 6)
#define RISCV_MMU_DIRTY        (1 << 7)
/* Use one of the ignored bits as SPECIAL. This will annotate zero page mappings (so we don't
 * increment mapcount on zero_page and thus blow it up). add_mapcount and sub_mapcount will not be
 * called on these struct pages. */
#define RISCV_MMU_SPECIAL      (1 << 8)
#define RISCV_PAGING_PROT_BITS ((1 << 9) - 1)

static unsigned long vm_prots_to_mmu(unsigned int prots)
{
    auto flags = (prots & VM_EXEC ? RISCV_MMU_EXECUTE : 0) |
                 (prots & VM_WRITE ? RISCV_MMU_WRITE : 0) | (prots & VM_READ ? RISCV_MMU_READ : 0) |
                 (prots & VM_USER ? RISCV_MMU_USER : RISCV_MMU_GLOBAL) | RISCV_MMU_VALID;

    if (!(prots & (VM_READ | VM_WRITE | VM_EXEC)))
        flags &= ~RISCV_MMU_VALID;

    return flags;
}

#define RISCV_MMU_FLAGS_TO_SAVE_ON_MPROTECT \
    (RISCV_MMU_GLOBAL | RISCV_MMU_USER | RISCV_MMU_ACCESSED | RISCV_MMU_DIRTY | RISCV_MMU_SPECIAL)

static inline void __native_tlb_invalidate_page(void *addr)
{
    __asm__ __volatile__("sfence.vma %0, zero" ::"r"(addr));
}

bool pte_empty(uint64_t pte)
{
    return pte == 0;
}

static inline bool pte_special(u64 pte)
{
    return pte & RISCV_MMU_SPECIAL;
}

unsigned long allocated_page_tables = 0;

PML *alloc_pt(void)
{
    struct page *p = alloc_page(0);
    if (p)
    {
        __atomic_add_fetch(&allocated_page_tables, 1, __ATOMIC_RELAXED);
    }

    return p != nullptr ? (PML *) pfn_to_paddr(page_to_pfn(p)) : nullptr;
}

PML *boot_pt;

PML *get_current_page_tables(void)
{
    struct process *p = get_current_process();
    if (!p)
        return boot_pt;
    return (PML *) p->address_space->arch_mmu.top_pt;
}

#define VERYHUGE512GB_SHIFT 39
#define VERYHUGE512GB_SIZE  (1UL << VERYHUGE512GB_SHIFT)
#define HUGE1GB_SHIFT       30
#define HUGE1GB_SIZE        0x40000000
#define LARGE2MB_SHIFT      21
#define LARGE2MB_SIZE       0x200000

static void addr_to_indices(unsigned long virt, unsigned int *indices)
{
    for (unsigned int i = 0; i < riscv_paging_levels; i++)
    {
        indices[i] = (virt >> 12) >> (i * 9) & 0x1ff;
    }
}

static bool pt_entry_is_huge(unsigned long pt_entry)
{
    return pt_entry & (RISCV_MMU_READ | RISCV_MMU_WRITE | RISCV_MMU_EXECUTE);
}

void *__virtual2phys(PML *__pml, void *ptr)
{
    unsigned long virt = (unsigned long) ptr;
    unsigned int indices[riscv_max_paging_levels];

    addr_to_indices(virt, indices);

    PML *pml = (PML *) ((uint64_t) __pml + PHYS_BASE);

    for (unsigned int i = riscv_paging_levels; i != 1; i--)
    {
        uint64_t entry = pml->entries[indices[i - 1]];

        if (!(entry & RISCV_MMU_VALID))
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

void __native_tlb_invalidate_all(void)
{
}

#define RISCV_SATP_ROOT_PT_MASK ((1UL << 44) - 1)

PML *riscv_get_top_page_table()
{
    unsigned long satp = riscv_read_csr(RISCV_SATP);

    return (PML *) ((satp & RISCV_SATP_ROOT_PT_MASK) << PAGE_SHIFT);
}

unsigned long riscv_make_pt_entry_page_table(PML *next_pt)
{
    return ((unsigned long) next_pt >> PAGE_SHIFT) << 10 | RISCV_MMU_VALID;
}

unsigned long riscv_pt_page_mapping(unsigned long paddr)
{
    return (paddr >> PAGE_SHIFT) << 10;
}

void paging_init(void)
{
    /* Get the current PML and store it */
    boot_pt = (PML *) riscv_get_top_page_table();
    /* Bootstrap the first 1GB */
    uintptr_t virt = PHYS_BASE;

    unsigned int indices[riscv_max_paging_levels];

    addr_to_indices(virt, indices);

    // Create two mappings of 512GB(1TB)
    auto flags = RISCV_MMU_WRITE | RISCV_MMU_READ | RISCV_MMU_GLOBAL | RISCV_MMU_VALID;
    boot_pt->entries[indices[riscv_paging_levels - 1]] = riscv_pt_page_mapping(0) | flags;
    boot_pt->entries[indices[riscv_paging_levels - 1] + 1] =
        riscv_pt_page_mapping(VERYHUGE512GB_SIZE) | flags;
}

bool pml_is_empty(const PML *pml)
{
    for (int i = 0; i < 512; i++)
    {
        if (pml->entries[i])
            return false;
    }

    return true;
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

    PML *p = (PML *) PHYS_TO_VIRT(new_pml);
    PML *curr = (PML *) PHYS_TO_VIRT(original->arch_mmu.top_pt);
    /* Copy the upper 256 entries of the PML in order to map
     * the kernel in the process's address space
     */

    memcpy(&p->entries[256], &curr->entries[256], 256 * sizeof(uint64_t));

    addr_space->arch_mmu.top_pt = new_pml;
    return 0;
}

void paging_load_top_pt(PML *pml)
{
    unsigned long new_satp = RISCV_SATP_4LEVEL_MMU | (unsigned long) pml >> PAGE_SHIFT;
    riscv_write_csr(RISCV_SATP, new_satp);
    __asm__ __volatile__("sfence.vma zero, %0" ::"r"(0));
}

static void dump_pt(PML *pt)
{
    for (const auto &entry : pt->entries)
        printk("%016lx\n", entry);
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
extern struct mm_address_space kernel_address_space;

void paging_protect_kernel(void)
{
    PML *original_pml = boot_pt;
    PML *pml = alloc_pt();
    assert(pml != NULL);
    boot_pt = pml;

    uintptr_t text_start = (uintptr_t) &_text_start;
    uintptr_t data_start = (uintptr_t) &_data_start;
    uintptr_t vdso_start = (uintptr_t) &_vdso_sect_start;

    memcpy((PML *) ((uintptr_t) pml + PHYS_BASE), (PML *) ((uintptr_t) original_pml + PHYS_BASE),
           sizeof(PML));
    PML *p = (PML *) ((uintptr_t) pml + PHYS_BASE);
    p->entries[511] = 0UL;
    p->entries[0] = 0UL;

    kernel_address_space.arch_mmu.top_pt = pml;

    size_t size = (uintptr_t) &_text_end - text_start;
    map_pages_to_vaddr((void *) text_start, (void *) (text_start - KERNEL_VIRTUAL_BASE), size,
                       VM_READ | VM_WRITE | VM_EXEC);

    size = (uintptr_t) &_data_end - data_start;
    map_pages_to_vaddr((void *) data_start, (void *) (data_start - KERNEL_VIRTUAL_BASE), size,
                       VM_READ | VM_WRITE);

    size = (uintptr_t) &_vdso_sect_end - vdso_start;
    map_pages_to_vaddr((void *) vdso_start, (void *) (vdso_start - KERNEL_VIRTUAL_BASE), size,
                       VM_READ | VM_WRITE);
    percpu_map_master_copy();

    paging_load_top_pt(pml);
}

unsigned long total_shootdowns = 0;

void paging_invalidate(void *page, size_t pages)
{
    uintptr_t p = (uintptr_t) page;

    for (size_t i = 0; i < pages; i++, p += PAGE_SIZE)
    {
        total_shootdowns++;
        __native_tlb_invalidate_page((void *) p);
    }
}

void paging_free_pml2(PML *pml)
{
    for (int i = 0; i < 512; i++)
    {
        const auto entry = pml->entries[i];
        if (entry & RISCV_MMU_VALID && !(pt_entry_is_huge(entry)))
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
    for (int i = 0; i < 512; i++)
    {
        if (pml->entries[i] & RISCV_MMU_VALID)
        {
            unsigned long phys_addr = PML_EXTRACT_ADDRESS(pml->entries[i]);
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
        if (pml->entries[i] & RISCV_MMU_VALID)
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
    paging_load_top_pt((PML *) mm->top_pt);
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

enum page_table_levels : unsigned int
{
    PT_LEVEL,
    PD_LEVEL,
    PDPT_LEVEL,
    PML4_LEVEL,
    PML5_LEVEL
};

static bool is_huge_page_level(unsigned int pt_level)
{
    // Every level is a huge page level in RISCV
    return true;
}

constexpr unsigned int level_to_entry_shift(unsigned int level)
{
    return (level * 9 + PAGE_SHIFT);
}

constexpr unsigned long level_to_entry_size(unsigned int level)
{
    return 1UL << level_to_entry_shift(level);
}

constexpr unsigned int addr_get_index(unsigned long virt, unsigned int pt_level)
{
    return (virt >> 12) >> (pt_level * 9) & 0x1ff;
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

void riscv_invalidate_tlb(void *context)
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

    smp::sync_call_with_local(riscv_invalidate_tlb, &info, mask, riscv_invalidate_tlb, &info);
}

struct mmu_acct
{
    size_t page_table_size;
    size_t resident_set_size;
    mm_address_space *as;
};

/**
 * @brief MMU accounting verifier helper. Takes a look at each page table.
 *
 * @param pt Pointer to page table.
 * @param level PT level we're at.
 * @param acct Reference mmu_acct structure.
 */
static void mmu_acct_page_table(PML *pt, page_table_levels level, mmu_acct &acct)
{
    acct.page_table_size += PAGE_SIZE;

    for (int i = 0; i < (level == PML4_LEVEL ? 256 : 512); i++)
    {
        u64 pte = pt->entries[i];
        if (pte_empty(pte))
            continue;

        if (level != PT_LEVEL)
        {
            mmu_acct_page_table((PML *) PHYS_TO_VIRT(PML_EXTRACT_ADDRESS(pte)),
                                (page_table_levels) (level - 1), acct);
        }
        else
        {
            acct.resident_set_size += level_to_entry_size(level);
        }
    }
}

/**
 * @brief Verifies the address space's accounting (RSS, PT Size)
 *
 * @param as The address space to verify.
 */
void mmu_verify_address_space_accounting(mm_address_space *as)
{
    mmu_acct acct{};
    acct.as = as;
    mmu_acct_page_table((PML *) PHYS_TO_VIRT(as->arch_mmu.top_pt), PML4_LEVEL, acct);

    assert(acct.page_table_size == as->page_tables_size);
    assert(acct.resident_set_size == as->resident_set_size);
}
