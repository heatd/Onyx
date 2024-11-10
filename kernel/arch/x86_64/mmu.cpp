/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <assert.h>
#include <cpuid.h>
#include <stdbool.h>
#include <stdio.h>

#include <onyx/cpu.h>
#include <onyx/page.h>
#include <onyx/paging.h>
#include <onyx/panic.h>
#include <onyx/pgtable.h>
#include <onyx/process.h>
#include <onyx/smp.h>
#include <onyx/vm.h>
#include <onyx/x86/control_regs.h>
#include <onyx/x86/pat.h>

#include <platform/kasan.h>

#define SUPPORT_LA57
#ifndef SUPPORT_LA57
#define CONST_LA48 const
#else
#define CONST_LA48
#endif

#define X86_PHYS_BASE_4L       (0xffffd00000000000)
#define X86_PHYS_BASE_LIMIT_4L (0xffffd08000000000)

#define X86_PHYS_BASE_5L       0xff11000000000000
#define X86_PHYS_BASE_LIMIT_5L 0xff91000000000000

#define X86_VM_HIGHER_HALF_4L 0xffff800000000000
#define X86_VM_HIGHER_HALF_5L 0xff00000000000000

#define X86_VM_LOWER_HALF_5L 0x00ffffffffffffff

unsigned long __x86_phys_base = X86_PHYS_BASE_4L;
unsigned long __x86_phys_base_limit = X86_PHYS_BASE_LIMIT_4L;
unsigned long __x86_vm_higher_half = X86_VM_HIGHER_HALF_4L;
unsigned long __x86_low_half_max = 0x00007fffffffffff;

extern "C"
{
CONST_LA48 unsigned int x86_paging_levels = 4;
}

static const unsigned int x86_max_paging_levels = 5;

#define X86_CACHING_BITS(index) ((((index) &0x3) << 3) | (((index >> 2) & 1) << 7))

#define PML_EXTRACT_ADDRESS(n)  ((n) &0x0FFFFFFFFFFFF000)
#define X86_PAGING_PRESENT      (1 << 0)
#define X86_PAGING_WRITE        (1 << 1)
#define X86_PAGING_USER         (1 << 2)
#define X86_PAGING_WRITETHROUGH (1 << 3)
#define X86_PAGING_PCD          (1 << 4)
#define X86_PAGING_ACCESSED     (1 << 5)
#define X86_PAGING_DIRTY        (1 << 6)
#define X86_PAGING_PAT          (1 << 7)
#define X86_PAGING_HUGE         (1 << 7)
#define X86_PAGING_GLOBAL       (1 << 8)
/* Use one of the ignored bits as SPECIAL. This will annotate zero page mappings (so we don't
 * increment mapcount on zero_page and thus blow it up). add_mapcount and sub_mapcount will not be
 * called on these struct pages. */
#define X86_PAGING_SPECIAL      (1 << 9)
#define X86_PAGING_NX           (1UL << 63)

#define X86_PAGING_PROT_BITS ((PAGE_SIZE - 1) | X86_PAGING_NX)

#define X86_PAGING_FLAGS_TO_SAVE_ON_MPROTECT                                        \
    (X86_PAGING_GLOBAL | X86_PAGING_HUGE | X86_PAGING_USER | X86_PAGING_ACCESSED |  \
     X86_PAGING_DIRTY | X86_PAGING_WRITETHROUGH | X86_PAGING_PCD | X86_PAGING_PAT | \
     X86_PAGING_SPECIAL)

__always_inline bool x86_is_pml5_enabled()
{
    return x86_paging_levels == 5;
}

static inline void __native_tlb_invalidate_page(void *addr)
{
    __asm__ __volatile__("invlpg (%0)" : : "b"(addr) : "memory");
}

bool x86_pte_empty(uint64_t pte)
{
    return pte == 0;
}

static inline bool pte_special(u64 pte)
{
    return pte & X86_PAGING_SPECIAL;
}

static inline uint64_t make_pml4e(uint64_t base, uint64_t avl, uint64_t pcd, uint64_t pwt,
                                  uint64_t us, uint64_t rw, uint64_t p)
{
    return (uint64_t) ((base) | (avl << 9) | (pcd << 4) | (pwt << 3) | (us << 2) | (rw << 1) | p);
}

static inline uint64_t make_pml3e(uint64_t base, uint64_t nx, uint64_t avl, uint64_t glbl,
                                  uint64_t pcd, uint64_t pwt, uint64_t us, uint64_t rw, uint64_t p)
{
    return (uint64_t) ((base) | (nx << 63) | (avl << 9) | (glbl << 8) | (pcd << 4) | (pwt << 3) |
                       (us << 2) | (rw << 1) | p);
}

static inline uint64_t make_pml2e(uint64_t base, uint64_t nx, uint64_t avl, uint64_t glbl,
                                  uint64_t pcd, uint64_t pwt, uint64_t us, uint64_t rw, uint64_t p)
{
    return (uint64_t) ((base) | (nx << 63) | (avl << 9) | (glbl << 8) | (pcd << 4) | (pwt << 3) |
                       (us << 2) | (rw << 1) | p);
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

PML *boot_pgd;
PML *init_pgd;

PML *get_current_pgd(void)
{
    struct process *p = get_current_process();
    if (!p)
        return init_pgd;
    return (PML *) p->address_space->arch_mmu.cr3;
}

#define HUGE1GB_SHIFT  30
#define HUGE1GB_SIZE   0x40000000
#define LARGE2MB_SHIFT 21
#define LARGE2MB_SIZE  0x200000

void x86_addr_to_indices(unsigned long virt, unsigned int *indices)
{
    for (unsigned int i = 0; i < x86_paging_levels; i++)
    {
        indices[i] = (virt >> 12) >> (i * 9) & 0x1ff;
    }
}

void *__virtual2phys(PML *__pml, void *ptr)
{
    unsigned long virt = (unsigned long) ptr;
    unsigned int indices[x86_max_paging_levels];

    x86_addr_to_indices(virt, indices);

    PML *pml = (PML *) ((uint64_t) __pml + PHYS_BASE);

    for (unsigned int i = x86_paging_levels; i != 1; i--)
    {
        uint64_t entry = pml->entries[indices[i - 1]];

        if (!(entry & X86_PAGING_PRESENT))
            return (void *) -1;

        if (entry & X86_PAGING_HUGE)
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
    return __virtual2phys(get_current_pgd(), ptr);
}

extern PML pdptphysical_map;
static PML pdphysical_map[4] __attribute__((aligned(PAGE_SIZE)));
static PML pml4physical_map __attribute__((aligned(PAGE_SIZE)));

static PML placement_mappings_page_dir __attribute__((aligned(4096)));
static PML placement_mappings_page_table __attribute__((aligned(4096)));

unsigned long placement_mappings_start = 0xffffffffffc00000;

#define EARLY_BOOT_GDB_DELAY              \
    volatile int __gdb_debug_counter = 0; \
    while (__gdb_debug_counter != 1)

void __native_tlb_invalidate_all(void)
{
    __asm__ __volatile__("mov %%cr3, %%rax\nmov %%rax, %%cr3" ::: "rax", "memory");
}

void *x86_placement_map(unsigned long _phys)
{
    if (_phys > placement_mappings_start)
        __asm__ __volatile__("ud2"); // HMMMMM, :thinking emoji:
    // printf("_phys: %lx\n", _phys);
    unsigned long phys = _phys & ~(PAGE_SIZE - 1);
    // printf("phys: %lx\n", phys);

    /* I'm not sure that kernel_address_space has been initialised yet, so we'll fill this with the
     * cr3 */
    kernel_address_space.arch_mmu.cr3 = get_current_pgd();

    /* Map two pages so memory that spans both pages can get accessed */
    vm_map_page(&kernel_address_space, placement_mappings_start, phys, VM_READ | VM_WRITE, nullptr);
    vm_map_page(&kernel_address_space, placement_mappings_start + PAGE_SIZE, phys + PAGE_SIZE,
                VM_READ | VM_WRITE, nullptr);
    __native_tlb_invalidate_page((void *) placement_mappings_start);
    __native_tlb_invalidate_page((void *) (placement_mappings_start + PAGE_SIZE));
    return (void *) (placement_mappings_start + (_phys - phys));
}

#define PA2VA(val) ((unsigned long) (val) + KERNEL_VIRTUAL_BASE - kernel_phys_offset)
#define VA2PA(val) ((unsigned long) (val) -KERNEL_VIRTUAL_BASE + kernel_phys_offset)

void x86_setup_placement_mappings(void)
{
    unsigned int indices[x86_max_paging_levels];
    const unsigned long virt = placement_mappings_start;

    PML *pml = (PML *) PA2VA(init_pgd);

    x86_addr_to_indices(virt, indices);

    for (unsigned int i = x86_paging_levels; i != 1; i--)
    {
        uint64_t entry = pml->entries[indices[i - 1]];
        if (entry & X86_PAGING_PRESENT)
        {
            void *page = (void *) PML_EXTRACT_ADDRESS(entry);
            pml = (PML *) PA2VA((PML *) page);
        }
        else
        {
            unsigned long page = 0;
            if (i == 3)
            {
                page = VA2PA(&placement_mappings_page_dir);
            }
            else if (i == 2)
            {
                page = VA2PA(&placement_mappings_page_table);
            }
            else
            {
                /* We only handle non-present page tables for PML1 and 2 */
                __asm__ __volatile__("cli; hlt");
            }

            pml->entries[indices[i - 1]] = make_pml3e(page, 0, 0, 1, 0, 0, 0, 1, 1);

            pml = (PML *) PA2VA((PML *) page);
        }
    }
}

extern "C"
{
int pgd_shift = 39, p4d_ptrs = 1;
}

NO_ASAN
void paging_init(void)
{
    if (x86_has_cap(X86_FEATURE_LA57))
    {
#ifndef SUPPORT_LA57
        __asm__ __volatile__("int3");
#else
        x86_paging_levels = 5;
        pgd_shift = 48;
        p4d_ptrs = 512;
        __x86_phys_base = X86_PHYS_BASE_5L;
        __x86_phys_base_limit = X86_PHYS_BASE_LIMIT_5L;
        __x86_vm_higher_half = X86_VM_HIGHER_HALF_5L;
        __x86_low_half_max = X86_VM_LOWER_HALF_5L;
#endif
    }

    /* Get the current PML and store it */
    __asm__ __volatile__("movq %%cr3, %%rax\t\nmovq %%rax, %0" : "=r"(boot_pgd)::"rax", "memory");
    init_pgd = boot_pgd;
    kernel_address_space.arch_mmu.cr3 = init_pgd;

    /* Bootstrap the first 4GB */
    uintptr_t virt = PHYS_BASE;
    PML *pml3 = (PML *) ((unsigned long) &pdptphysical_map + get_kernel_phys_offset());
    PML *pml4 = (PML *) PA2VA(init_pgd);

    unsigned int indices[x86_max_paging_levels];
    x86_addr_to_indices(virt, indices);

    if (x86_is_pml5_enabled())
    {
        /* if we're running under PML5, set up the PML4 level */
        auto pml5 = pml4;
        pml4 = &pml4physical_map;
        pml5->entries[indices[x86_paging_levels - 1]] =
            VA2PA(&pml4physical_map) | X86_PAGING_WRITE | X86_PAGING_PRESENT | X86_PAGING_NX;
    }

    pml4->entries[indices[x86_paging_levels - 1 - x86_is_pml5_enabled()]] =
        make_pml4e((uint64_t) pml3, 0, 0, 0, 0, 1, 1);
    auto pdphysmap_phys = VA2PA(&pdphysical_map);

    pml3 = (PML *) ((unsigned long) &pdptphysical_map + KERNEL_VIRTUAL_BASE);
    for (unsigned int i = 0; i < 4; i++)
    {
        pml3->entries[i] = make_pml3e(pdphysmap_phys + 0x1000 * i, 0, 0, 1, 0, 0, 0, 1, 1);

        for (size_t j = 0; j < 512; j++)
        {
            uintptr_t p = (i << HUGE1GB_SHIFT) + (j << LARGE2MB_SHIFT);

            pdphysical_map[i].entries[j] = p | X86_PAGING_WRITE | X86_PAGING_PRESENT |
                                           X86_PAGING_NX | X86_PAGING_HUGE | X86_PAGING_GLOBAL;
        }
    }

    x86_setup_placement_mappings();
}

NO_ASAN
void paging_map_all_phys()
{
    bool is_1gb_supported = x86_has_cap(X86_FEATURE_PDPE1GB);

    printf("Is 1gb supported? %s\n", is_1gb_supported ? "yes" : "no");
    uintptr_t virt = PHYS_BASE;

    /* The PDPT is already hooked up to a PML4, so we only need to deal with the lower levels */
    PML *pml3 = (PML *) ((unsigned long) &pdptphysical_map + KERNEL_VIRTUAL_BASE);
    u64 *entry;

    if (is_1gb_supported)
    {
        for (size_t i = 0; i < 512; i++)
        {
            entry = &pml3->entries[i];
            *entry = make_pml3e(i * HUGE1GB_SIZE, 1, 0, 1, 0, 0, 0, 1, 1);
            *entry |= X86_PAGING_HUGE;
        }
    }
    else
    {
        PML new_pml3;
        /* Use 2MiB pages instead */
        entry = &new_pml3.entries[0];
        for (size_t i = 0; i < 512; i++)
        {
            void *ptr = alloc_boot_page(1, 0);

            assert(ptr != NULL);

            *entry = make_pml3e(((unsigned long) ptr), 1, 0, 1, 0, 0, 0, 1, 1);

            PML *pd = (PML *) x86_placement_map((unsigned long) ptr);

            for (size_t j = 0; j < 512; j++)
            {
                uintptr_t p = (i << HUGE1GB_SHIFT) + (j << LARGE2MB_SHIFT);

                pd->entries[j] = p | X86_PAGING_WRITE | X86_PAGING_PRESENT | X86_PAGING_NX |
                                 X86_PAGING_HUGE | X86_PAGING_GLOBAL;
            }

            entry++;
        }

        memcpy(pml3, &new_pml3, sizeof(PML));
    }

    for (size_t i = 0; i < 512; i++)
        __native_tlb_invalidate_page((void *) (virt + i * 0x40000000));
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
    scoped_lock g2{original->page_table_lock};

    PML *new_pml = alloc_pt();
    if (!new_pml)
        return -ENOMEM;

    addr_space->page_tables_size = PAGE_SIZE;

    PML *p = (PML *) PHYS_TO_VIRT(new_pml);
    PML *curr = (PML *) PHYS_TO_VIRT(original->arch_mmu.cr3);
    /* Copy the upper 256 entries of the PML in order to map
     * the kernel in the process's address space
     */

    memcpy(&p->entries[256], &curr->entries[256], 256 * sizeof(uint64_t));

    addr_space->arch_mmu.cr3 = new_pml;
    return 0;
}

void paging_load_cr3(PML *pml)
{
    assert(pml != NULL);
    PML *oldpml;

    __asm__ __volatile__("movq %%cr3, %0" : "=r"(oldpml));
    if (oldpml == pml)
        return;
    __asm__ __volatile__("movq %0, %%cr3" ::"r"(pml));
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
extern struct mm_address_space kernel_address_space;

void kasan_remap_shadow_la57(PML *pml, PML *bootpgd);

void paging_protect_kernel(void)
{
    PML *original_pml = init_pgd;
    PML *pml = alloc_pt();
    assert(pml != nullptr);
    init_pgd = pml;

    uintptr_t text_start = (uintptr_t) &_text_start;
    uintptr_t data_start = (uintptr_t) &_data_start;

    memcpy(PHYS_TO_VIRT(pml), PHYS_TO_VIRT(original_pml), sizeof(PML));
    PML *p = (PML *) PHYS_TO_VIRT(pml);
    p->entries[511] = 0UL;
    p->entries[0] = 0UL;

    kernel_address_space.arch_mmu.cr3 = pml;

    size_t size = (uintptr_t) &_text_end - text_start;
    map_pages_to_vaddr((void *) text_start, (void *) VA2PA(text_start), size, VM_READ | VM_EXEC);

    size = (uintptr_t) &_data_end - data_start;
    map_pages_to_vaddr((void *) data_start, (void *) VA2PA(data_start), size, VM_WRITE | VM_READ);

    percpu_map_master_copy();

#ifdef CONFIG_KASAN
    // On LA57, our KASAN shadow bleeds into the last PML5e
    // so we must remap that bit. map_pages_to_vaddr will have populated this PML4e.
    if (x86_is_pml5_enabled())
    {
        kasan_remap_shadow_la57((PML *) PHYS_TO_VIRT(pml), (PML *) PHYS_TO_VIRT(original_pml));
    }
#endif

    // Report PML5 now that we have a log up
    if (x86_is_pml5_enabled())
        printf("x86: LA57 enabled\n");

    __asm__ __volatile__("movq %0, %%cr3" ::"r"(pml));
}

unsigned long total_shootdowns = 0;

static void __native_tlb_invalidate_global()
{
    // Disable IRQs, toggle CR4, enable IRQs is the sequence
    // we need to safely flush all global mappings
    const auto flags = irq_save_and_disable();

    auto old = x86_read_cr4();
    x86_write_cr4(old & ~CR4_PGE);
    x86_write_cr4(old);

    irq_restore(flags);
}

void paging_invalidate(void *page, size_t pages)
{
    uintptr_t p = (uintptr_t) page;

    // Determined from the default linux /sys/kernel/debug/x86/tlb_single_page_flush_ceiling
    if (pages > 32)
    {
        if ((unsigned long) page >= VM_HIGHER_HALF)
            __native_tlb_invalidate_global();
        else
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
    for (int i = 0; i < 512; i++)
    {
        if (pml->entries[i] & X86_PAGING_PRESENT && !(pml->entries[i] & X86_PAGING_HUGE))
        {
            /* We don't need to free pages since these functions
             * are supposed to only tear down paging tables */
            unsigned long phys_addr = PML_EXTRACT_ADDRESS(pml->entries[i]);

            free_page(phys_to_page(phys_addr));
        }
    }
}

void paging_free_pml3(PML *pml)
{
    for (int i = 0; i < 512; i++)
    {
        if (pml->entries[i] & X86_PAGING_PRESENT)
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
    PML *pml = (PML *) PHYS_TO_VIRT(mm->arch_mmu.cr3);

    for (int i = 0; i < 256; i++)
    {
        if (pml->entries[i] & X86_PAGING_PRESENT)
        {
            unsigned long phys_addr = PML_EXTRACT_ADDRESS(pml->entries[i]);
            PML *pml3 = (PML *) PHYS_TO_VIRT(phys_addr);
            paging_free_pml3(pml3);

            free_page(phys_to_page(phys_addr));
            pml->entries[i] = 0;
        }
    }

    free_page(phys_to_page((unsigned long) mm->arch_mmu.cr3));
}

/**
 * @brief Free the architecture dependent parts of the address space.
 * Called on address space destruction.
 *
 * @param mm The to-be-destroyed address space.
 */
void vm_free_arch_mmu(struct arch_mm_address_space *mm)
{
    free_page(phys_to_page((unsigned long) mm->cr3));
}

/**
 * @brief Loads a new address space.
 *
 * @param mm The to-be-loaded address space.
 */
void vm_load_arch_mmu(struct arch_mm_address_space *mm)
{
    paging_load_cr3((PML *) mm->cr3);
}

/**
 * @brief Saves the current address space in \p mm
 *
 * @param mm A pointer to a valid mm_address_space.
 */
void vm_save_current_mmu(struct mm_address_space *mm)
{
    mm->arch_mmu.cr3 = get_current_pgd();
}

enum x86_page_table_levels : unsigned int
{
    PT_LEVEL,
    PD_LEVEL,
    PDPT_LEVEL,
    PML4_LEVEL,
    PML5_LEVEL
};

static bool is_huge_page_level(unsigned int pt_level)
{
    constexpr unsigned int pdpt_level = PDPT_LEVEL, pd_level = PD_LEVEL;

    return pt_level == pdpt_level || pt_level == pd_level;
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

void x86_invalidate_tlb(void *context)
{
    auto info = (mm_shootdown_info *) context;
    auto addr = info->addr;
    auto pages = info->pages;
    auto addr_space = info->mm;

    auto curr_thread = get_current_thread();

    if (is_higher_half(addr) || (curr_thread->owner && curr_thread->get_aspace() == addr_space))
    {
        paging_invalidate((void *) addr, pages);
        add_per_cpu(tlb_nr_invals, 1);
    }
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

    smp::sync_call_with_local(x86_invalidate_tlb, &info, mask, x86_invalidate_tlb, &info);
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
static void mmu_acct_page_table(PML *pt, x86_page_table_levels level, mmu_acct &acct)
{
    acct.page_table_size += PAGE_SIZE;

    for (const auto pte : pt->entries)
    {
        if (x86_pte_empty(pte))
            continue;

        if (!(pte & X86_PAGING_USER))
            continue;

        if (level != PT_LEVEL)
        {
            mmu_acct_page_table((PML *) PHYS_TO_VIRT(PML_EXTRACT_ADDRESS(pte)),
                                (x86_page_table_levels) (level - 1), acct);
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
    mmu_acct_page_table((PML *) PHYS_TO_VIRT(as->arch_mmu.cr3),
                        x86_is_pml5_enabled() ? PML5_LEVEL : PML4_LEVEL, acct);

    assert(acct.page_table_size == as->page_tables_size);
    assert(acct.resident_set_size == as->resident_set_size);
}

void x86_remap_top_pgd_to_top_pgd(unsigned long source, unsigned long dest)
{
    unsigned int indices0[x86_max_paging_levels];
    unsigned int indices1[x86_max_paging_levels];
    x86_addr_to_indices(source, indices0);
    x86_addr_to_indices(dest, indices1);
    auto top = (PML *) PHYS_TO_VIRT(get_current_pgd());
    top->entries[indices1[x86_paging_levels - 1]] = top->entries[indices0[x86_paging_levels - 1]];
    top->entries[indices0[x86_paging_levels - 1]] = 0;
    __native_tlb_invalidate_all();
}

#ifdef CONFIG_KASAN

unsigned long __x86_kasan_virt;

#define KASAN_VIRTUAL_5L 0xffdf000000000000
#define KASAN_VIRTUAL_4L 0xffffec0000000000
#define KASAN_4L_END     0xfffffbffffffffff

extern "C" char x86_stack_bottom[];
extern "C" char kasan_shadow_page_tables[];
static PML *shadow_pml4, *shadow_pdpt, *shadow_pd, *shadow_pt;
static unsigned long *zero_shadow_map;

static inline char *kasan_get_ptr(unsigned long addr)
{
    return (char *) KASAN_SHADOW_OFFSET + (addr >> 3);
}

#define PTE_INDEX(virt, level) ((((virt) >> 12) >> (((level) -1) * 9)) & 0x1ff)

void kasan_remap_shadow_la57(PML *top_pgd, PML *bootpgd)
{
    // Similar idea to kasan_map_shadow_la57, but we copy the boot pgd's entries instead.
    // Why? Because we have un-cow'ed some PTEs (at least our stack).
    constexpr unsigned int last_pml5e = PTE_INDEX(KASAN_4L_END, 5);
    PML *old_pml4 = (PML *) PHYS_TO_VIRT(PML_EXTRACT_ADDRESS(bootpgd->entries[last_pml5e]));
    PML *last_pml4 = (PML *) PHYS_TO_VIRT(PML_EXTRACT_ADDRESS(top_pgd->entries[last_pml5e]));
    constexpr unsigned int last_pml4e = PTE_INDEX(KASAN_4L_END, 4) + 1;
    for (unsigned int i = 0; i < last_pml4e; i++)
    {
        last_pml4->entries[i] = old_pml4->entries[i];
    }
}

NO_ASAN void kasan_map_shadow_la57(PML *top_pgd, PML *new_pml4)
{
    /* "I wonder if we can use the same offset for both modes. If we use
       0xFFDFFC0000000000 as start of shadow for 5 levels, then the same
       offset that we use for 4 levels (0xdffffc0000000000) will also work
       for 5 levels. Namely, ending of 5 level shadow will overlap with 4
       level mapping (both end at 0xfffffbffffffffff), but 5 level mapping
       extends towards lower addresses. The current 5 level start of shadow
       is actually close -- 0xffd8000000000000 and it seems that the required
       space after it is unused at the moment (at least looking at mm.txt).
       So just try to move it to 0xFFDFFC0000000000?" - dvyukov, on Linux PML5 KASAN support

       We follow the same approach. The last PML4 will have its [0, PTE_INDEX(KASAN_4L_END)]
       occupied with shadow PDPTs.
    */
    PML *last_pml4 = (PML *) PML_EXTRACT_ADDRESS(top_pgd->entries[PTE_INDEX(KASAN_4L_END, 5)]);
    constexpr unsigned int last_pml4e = PTE_INDEX(KASAN_4L_END, 4) + 1;

    /* Since early ASM for identity mapping maps pml5[0] = pml5[511], we'll make a copy and use that
     * one, since SMP bootstrap will require that same identity mapping, later.
     */

    for (unsigned int i = 0; i < last_pml4e; i++)
    {
        new_pml4->entries[i] = VA2PA(shadow_pdpt) | X86_PAGING_PRESENT | X86_PAGING_NX;
    }

    for (unsigned int i = last_pml4e; i < PAGE_TABLE_ENTRIES; i++)
    {
        new_pml4->entries[i] = last_pml4->entries[i];
        COMPILER_BARRIER(); // Make sure the compiler doesn't transform this into a memcpy
    }

    top_pgd->entries[PTE_INDEX(KASAN_4L_END, 5)] =
        VA2PA(new_pml4) | X86_PAGING_PRESENT | X86_PAGING_WRITE;
}

extern "C" NO_ASAN void x86_bootstrap_kasan(bool la57)
{
    PML *top_pgd;
    PML *shadow_pts = (PML *) kasan_shadow_page_tables;
    __asm__ __volatile__("mov %%cr3, %0" : "=r"(top_pgd));
    unsigned int indices[x86_max_paging_levels];

    x86_paging_levels = la57 ? 5 : 4;

    __x86_kasan_virt = la57 ? KASAN_VIRTUAL_5L : KASAN_VIRTUAL_4L;

    for (unsigned int i = 0; i < x86_paging_levels; i++)
    {
        indices[i] = (__x86_kasan_virt >> 12) >> (i * 9) & 0x1ff;
    }

    for (unsigned int i = 0; i < 32; i++)
    {
        top_pgd->entries[indices[x86_paging_levels - 1] + i] =
            VA2PA(shadow_pts) | X86_PAGING_PRESENT | X86_PAGING_NX;
    }

    shadow_pdpt = shadow_pts;

    if (la57)
    {
        shadow_pml4 = shadow_pdpt;
        shadow_pdpt = ++shadow_pts;
        // Fill the shadow pml4
        for (unsigned int i = 0; i < 512; i++)
        {
            shadow_pml4->entries[i] = VA2PA(shadow_pdpt) | X86_PAGING_PRESENT | X86_PAGING_NX;
        }

        kasan_map_shadow_la57(top_pgd, ++shadow_pts);
    }

    shadow_pd = ++shadow_pts;
    for (unsigned int i = 0; i < 512; i++)
    {
        shadow_pdpt->entries[i] = VA2PA(shadow_pd) | X86_PAGING_PRESENT | X86_PAGING_NX;
    }

    shadow_pt = ++shadow_pts;

    for (unsigned int i = 0; i < 512; i++)
    {
        shadow_pd->entries[i] = VA2PA(shadow_pt) | X86_PAGING_PRESENT | X86_PAGING_NX;
    }

    zero_shadow_map = (unsigned long *) ++shadow_pts;
    for (unsigned int i = 0; i < 512; i++)
    {
        shadow_pt->entries[i] =
            VA2PA(zero_shadow_map) | X86_PAGING_PRESENT | X86_PAGING_GLOBAL | X86_PAGING_NX;
    }

    // Map a page for the kernel stack, since the compiler generates code to write to it

    unsigned long cowable_pagetables[x86_max_paging_levels];
    cowable_pagetables[0] = VA2PA(shadow_pml4);
    cowable_pagetables[1] = VA2PA(shadow_pdpt);
    cowable_pagetables[2] = VA2PA(shadow_pd);
    cowable_pagetables[3] = VA2PA(shadow_pt);
    cowable_pagetables[4] = VA2PA(zero_shadow_map);

    // Used to offset in cowable_pagetables
    const unsigned int no_la57 = !la57;

    /* Note: page table flags are different from page perms because a page table's
     * permissions apply throughout the whole table.
     * Because of that, the PT's flags are Present | Write | (possible User)
     */
    uint64_t page_table_flags = X86_PAGING_PRESENT | X86_PAGING_WRITE;

    auto virt = (unsigned long) kasan_get_ptr((unsigned long) &x86_stack_bottom);

    for (unsigned int i = 0; i < x86_paging_levels; i++)
    {
        indices[i] = (virt >> 12) >> (i * 9) & 0x1ff;
    }

    PML *pml = top_pgd;

    for (unsigned int i = x86_paging_levels; i != 1; i--)
    {
        auto oldpml = pml;
        uint64_t entry = pml->entries[indices[i - 1]];
        if (!(entry & X86_PAGING_PRESENT))
        {
            panic("Shadow does not have valid page table");
        }

        void *page = (void *) PML_EXTRACT_ADDRESS(entry);
        pml = (PML *) PA2VA(page);
        if ((unsigned long) page != cowable_pagetables[x86_paging_levels - i + no_la57])
            continue;

        auto newpml = ++shadow_pts;

        // Copy the old page table
        __memcpy(newpml, pml, PAGE_SIZE);

        oldpml->entries[indices[i - 1]] = (uint64_t) VA2PA(newpml) | page_table_flags;
        pml = (PML *) newpml;
    }

    auto &entry = pml->entries[indices[0]];

    assert(entry & X86_PAGING_PRESENT);
    if (PML_EXTRACT_ADDRESS(entry) == cowable_pagetables[4])
    {
        PML *p = ++shadow_pts;
        entry = (unsigned long) VA2PA(p) | X86_PAGING_WRITE | X86_PAGING_GLOBAL | X86_PAGING_NX |
                X86_PAGING_PRESENT;
    }
    else
    {
        assert(entry & X86_PAGING_WRITE);
    }
}

int mmu_map_real_shadow(unsigned long virt)
{
    unsigned int indices[x86_max_paging_levels];
    unsigned long cowable_pagetables[x86_max_paging_levels];
    cowable_pagetables[0] = VA2PA(shadow_pml4);
    cowable_pagetables[1] = VA2PA(shadow_pdpt);
    cowable_pagetables[2] = VA2PA(shadow_pd);
    cowable_pagetables[3] = VA2PA(shadow_pt);
    cowable_pagetables[4] = VA2PA(zero_shadow_map);

    // Used to offset in cowable_pagetables
    const unsigned int no_la57 = !x86_is_pml5_enabled();

    /* Note: page table flags are different from page perms because a page table's
     * permissions apply throughout the whole table.
     * Because of that, the PT's flags are Present | Write | (possible User)
     */
    uint64_t page_table_flags = X86_PAGING_PRESENT | X86_PAGING_WRITE;

    x86_addr_to_indices(virt, indices);

    PML *pml = (PML *) PHYS_TO_VIRT(get_current_pgd());

    for (unsigned int i = x86_paging_levels; i != 1; i--)
    {
        auto oldpml = pml;
        uint64_t entry = pml->entries[indices[i - 1]];
        if (!(entry & X86_PAGING_PRESENT))
        {
            panic("Shadow does not have valid page table");
        }

        void *page = (void *) PML_EXTRACT_ADDRESS(entry);
        pml = (PML *) PHYS_TO_VIRT(page);
        if ((unsigned long) page != cowable_pagetables[x86_paging_levels - i + no_la57])
            continue;

        page = alloc_pt();
        if (!page)
            return -ENOMEM;

        // Copy the old page table
        __memcpy(PHYS_TO_VIRT(page), pml, PAGE_SIZE);

        increment_vm_stat((&kernel_address_space), page_tables_size, PAGE_SIZE);
        oldpml->entries[indices[i - 1]] = (uint64_t) page | page_table_flags;
        pml = (PML *) PHYS_TO_VIRT(page);
    }

    auto &entry = pml->entries[indices[0]];

    assert(entry & X86_PAGING_PRESENT);
    if (PML_EXTRACT_ADDRESS(entry) == cowable_pagetables[4])
    {
        // Create a new shadow page
        struct page *p = alloc_page(0);
        if (!p)
            return -ENOMEM;
        entry = (unsigned long) page_to_phys(p) | X86_PAGING_WRITE | X86_PAGING_GLOBAL |
                X86_PAGING_NX | X86_PAGING_PRESENT;
        return 1;
    }
    else
    {
        assert(entry & X86_PAGING_WRITE);
    }

    return 0;
}

int mmu_map_kasan_shadow(void *shadow_start, size_t pages)
{
    scoped_lock g{kernel_address_space.page_table_lock};
    bool invalidate = false;

    for (size_t i = 0; i < pages; i++)
    {
        int st = mmu_map_real_shadow(((unsigned long) shadow_start) + (i << PAGE_SHIFT));
        if (st < 0)
            return -ENOMEM;
        invalidate = invalidate ? invalidate : st == 1;
    }

    // TODO: Be smart about invalidation
    if (invalidate)
        mmu_invalidate_range((unsigned long) shadow_start, pages, &kernel_address_space);

    return 0;
}

static void pte_kasan_range(pte_t *pte, unsigned long start, unsigned long end)
{
    unsigned long zero_shadow = VA2PA(zero_shadow_map);
    unsigned long next_start;
    for (; start < end; pte++, start = next_start)
    {
        next_start = min(pte_addr_end(start), end);
        pte_t old = *pte;
        if (pte_addr(old) != zero_shadow)
        {
            CHECK(pte_write(old));
            continue;
        }

        void *shadow = alloc_boot_page(1, 0);
        memset(PHYS_TO_VIRT(shadow), 0, PAGE_SIZE);
        set_pte(pte, pte_mkpte((u64) shadow,
                               __pgprot(_PAGE_WRITE | _PAGE_PRESENT | _PAGE_NX | _PAGE_GLOBAL)));
    }
}

#define SHADOW(type, hwtype) (VA2PA(shadow_##hwtype))

static void pmd_kasan_range(pmd_t *pmd, unsigned long start, unsigned long end)
{
    pte_t *pte;
    unsigned long next_start;
    for (; start < end; pmd++, start = next_start)
    {
        next_start = min(pmd_addr_end(start), end);
        if (pmd_none(*pmd))
            continue;
        DCHECK(!pmd_huge(*pmd));
        pte = pte_offset(pmd, start);
        if (pmd_addr(*pmd) == SHADOW(pte, pt))
        {
            pte_t *newpte = (pte_t *) alloc_boot_page(1, 0);
            memcpy(PHYS_TO_VIRT(newpte), shadow_pt, PAGE_SIZE);
            set_pmd(pmd, pmd_mkpmd((unsigned long) newpte, __pgprot(KERNEL_PGTBL)));
            pte = pte_offset(pmd, start);
        }

        CHECK(pmd_val(*pmd) & (_PAGE_WRITE | _PAGE_PRESENT));
        pte_kasan_range(pte, start, next_start);
    }
}

static void pud_kasan_range(pud_t *pud, unsigned long start, unsigned long end)
{
    pmd_t *pmd;
    unsigned long next_start;
    for (; start < end; pud++, start = next_start)
    {
        next_start = min(pud_addr_end(start), end);
        if (pud_none(*pud))
            continue;
        DCHECK(!pud_huge(*pud));
        pmd = pmd_offset(pud, start);
        if (pud_addr(*pud) == SHADOW(pmd, pd))
        {
            pmd_t *newpmd = (pmd_t *) alloc_boot_page(1, 0);
            memcpy(PHYS_TO_VIRT(newpmd), shadow_pd, PAGE_SIZE);
            set_pud(pud, pud_mkpud((unsigned long) newpmd, __pgprot(KERNEL_PGTBL)));
            pmd = pmd_offset(pud, start);
        }

        CHECK(pud_val(*pud) & (_PAGE_WRITE | _PAGE_PRESENT));
        pmd_kasan_range(pmd, start, next_start);
    }
}

static void p4d_kasan_range(p4d_t *p4d, unsigned long start, unsigned long end)
{
    pud_t *pud;
    unsigned long next_start;
    for (; start < end; p4d++, start = next_start)
    {
        next_start = min(p4d_addr_end(start), end);
        if (WARN_ON(p4d_none(*p4d)))
            continue;
        DCHECK(!p4d_huge(*p4d));
        pud = pud_offset(p4d, start);
        if (p4d_addr(*p4d) == SHADOW(pud, pdpt))
        {
            pud_t *newpud = (pud_t *) alloc_boot_page(1, 0);
            memcpy(PHYS_TO_VIRT(newpud), shadow_pdpt, PAGE_SIZE);
            set_p4d(p4d, p4d_mkp4d((unsigned long) newpud, __pgprot(KERNEL_PGTBL)));
            pud = pud_offset(p4d, start);
        }

        CHECK(p4d_val(*p4d) & (_PAGE_WRITE | _PAGE_PRESENT));
        pud_kasan_range(pud, start, next_start);
    }
}

static void pgd_kasan_range(pgd_t *pgd, unsigned long start, unsigned long end)
{
    p4d_t *p4d;
    unsigned long next_start;
    for (; start < end; pgd++, start = next_start)
    {
        next_start = min(pgd_addr_end(start), end);
        if (WARN_ON(pgd_none(*pgd)))
            continue;
        p4d = p4d_offset(pgd, start);
        if (pml5_present() && pgd_addr(*pgd) == SHADOW(p4d, pml4))
        {
            p4d_t *newp4d = (p4d_t *) alloc_boot_page(1, 0);
            memcpy(PHYS_TO_VIRT(newp4d), shadow_pml4, PAGE_SIZE);
            set_pgd(pgd, pgd_mkpgd((unsigned long) newp4d, __pgprot(KERNEL_PGTBL)));
            p4d = p4d_offset(pgd, start);
        }

        p4d_kasan_range(p4d, start, next_start);
    }
}

void init_shadow_for_phys(unsigned long addr, size_t len)
{
    unsigned long start = (unsigned long) kasan_get_ptr((unsigned long) PHYS_TO_VIRT(addr));
    unsigned long end = ALIGN_TO(start + (len >> 3), PAGE_SIZE);
    pr_info("kasan: initializing shadow for [%lx, %lx] (%lx, %lx)\n", addr, addr + len - 1, start,
            end - 1);
    pgd_t *pgd = pgd_offset(&kernel_address_space, start);
    pgd_kasan_range(pgd, start, end);
    mmu_invalidate_range(start, (end - start) >> PAGE_SHIFT, &kernel_address_space);
}

#endif
