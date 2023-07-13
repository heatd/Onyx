/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
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
#include <onyx/process.h>
#include <onyx/serial.h>
#include <onyx/smp.h>
#include <onyx/vm.h>

static char buffer[1000];

#define budget_printk(...)                         \
    snprintf(buffer, sizeof(buffer), __VA_ARGS__); \
    platform_serial_write(buffer, strlen(buffer))

static const unsigned int arm64_paging_levels = 4;
static const unsigned int arm64_max_paging_levels = 5;
#define ARM64_MMU_PERM_MASK 0xfff8000000000ffful

// Page table entries have the top bits reserved (63 - 51) and the lower 12 bits
// clang format note: it's misformatting the macro
// clang-format off
#define PML_EXTRACT_ADDRESS(n) ((n) & ~ARM64_MMU_PERM_MASK)
#define PML_EXTRACT_PERMS(n) ((n) & ARM64_MMU_PERM_MASK)
// clang-format on

static unsigned long vm_prots_to_mmu(unsigned int prots)
{
    auto flags = (prots & VM_READ && !(prots & VM_WRITE) ? ARM64_MMU_READ_ONLY : 0) |
                 (prots & VM_USER ? (ARM64_MMU_EL0 | ARM64_MMU_nG) : 0) | ARM64_MMU_VALID |
                 ARM64_MMU_AF | ARM64_MMU_PAGE;
    if (prots & VM_USER)
    {
        flags |= ARM64_MMU_PXN;
        flags |= (prots & VM_EXEC ? 0 : ARM64_MMU_XN);
    }
    else
    {
        flags |= ARM64_MMU_XN;
        flags |= (prots & VM_EXEC ? 0 : ARM64_MMU_PXN);
    }

    flags |= ARM64_MMU_INNER_SHAREABLE | MMU_PTR_ATTR_NORMAL_MEMORY;

    if (!(prots & (VM_READ | VM_WRITE | VM_EXEC)))
        flags &= ~ARM64_MMU_VALID;

    return flags;
}

#define ARM64_MMU_FLAGS_TO_SAVE_ON_MPROTECT \
    (ARM64_MMU_nG | ARM64_MMU_EL0 | ARM64_MMU_AF | ARM64_MMU_PAGE)

void *paging_map_phys_to_virt(struct mm_address_space *as, uint64_t virt, uint64_t phys,
                              uint64_t prot);

static inline void __native_tlb_invalidate_page(void *addr)
{
    // TODO: ASIDs
    __asm__ __volatile__("tlbi vaae1is, %0" ::"r"((unsigned long) addr >> 12));
    isb();
}

bool pte_empty(uint64_t pte)
{
    return pte == 0;
}

bool arm64_get_pt_entry(void *addr, uint64_t **entry_ptr, bool may_create_path,
                        struct mm_address_space *mm);

unsigned long allocated_page_tables = 0;

PML *alloc_pt()
{
    struct page *p = alloc_page(0);
    if (p)
    {
        __atomic_add_fetch(&allocated_page_tables, 1, __ATOMIC_RELAXED);
    }

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
    dsb();
    isb();
}

PML *arm64_get_kernel_page_table()
{
    return (PML *) mrs(REG_TTBR1);
}

unsigned long arm64_make_pt_entry_page_table(PML *next_pt)
{
    auto next_pt_long = (unsigned long) next_pt;
    return next_pt_long | ARM64_MMU_TABLE | ARM64_MMU_VALID | ARM64_MMU_INNER_SHAREABLE |
           ARM64_MMU_AF | MMU_PTR_ATTR_NORMAL_MEMORY;
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

static void arm64_set_pte(void *vaddr, u64 *pte, u64 newpte)
{
    u64 old = read_once(*pte);

    if (old != 0)
    {
        // If a valid entry, do BBM
        write_once(*pte, (u64) 0);
        // Now do a dsb to make sure the entry is written back
        dsb();
        // Invalidate the page, broadcast
        __native_tlb_invalidate_page(vaddr);

        // dsb will wait for the tlbi
        dsb();
    }

    // Write the new pte entry and dsb
    write_once(*pte, newpte);
    dsb();
}

void *paging_map_phys_to_virt(struct mm_address_space *as, uint64_t virt, uint64_t phys,
                              uint64_t prot)
{
    bool user = false;
    if (virt < 0x00007fffffffffff)
        user = true;

    if (!as && user)
    {
        as = get_current_address_space();
    }
    else if (!user)
        as = &kernel_address_space;

    uint64_t *ptentry;

    if (!arm64_get_pt_entry((void *) virt, &ptentry, true, as))
        return nullptr;

    uint64_t page_prots = vm_prots_to_mmu(prot);
#if 0
    printk("mapping %016lx vm prots %c%c%c page %016lx prots %016lx\n", virt,
           prot & VM_READ ? 'r' : '-', prot & VM_WRITE ? 'w' : '-', prot & VM_EXEC ? 'x' : '-',
           phys, page_prots);
#endif
    if (prot & VM_DONT_MAP_OVER && *ptentry & ARM64_MMU_VALID)
        return (void *) virt;

    uint64_t old = read_once(*ptentry);

    // set_pte properly invalidates the TLB, so we don't need to
    arm64_set_pte((void *) virt, ptentry, page_prots | phys);

    if (pte_empty(old))
    {
        increment_vm_stat(as, resident_set_size, PAGE_SIZE);
    }

    isb();

    return (void *) virt;
}

bool pml_is_empty(const PML *pml)
{
    for (unsigned long entry : pml->entries)
    {
        if (entry)
            return false;
    }

    return true;
}

struct pt_location
{
    PML *table;
    unsigned int index;
};

bool arm64_get_pt_entry_with_ptables(void *addr, uint64_t **entry_ptr, struct mm_address_space *mm,
                                     struct pt_location location[4])
{
    unsigned long virt = (unsigned long) addr;
    unsigned int indices[arm64_max_paging_levels];

    for (unsigned int i = 0; i < arm64_paging_levels; i++)
    {
        indices[i] = (virt >> 12) >> (i * 9) & 0x1ff;
        location[4 - 1 - i].index = indices[i];
    }

    PML *pml = (PML *) ((unsigned long) mm->arch_mmu.top_pt + PHYS_BASE);
    unsigned int location_index = 0;

    for (unsigned int i = arm64_paging_levels; i != 1; i--)
    {
        uint64_t entry = pml->entries[indices[i - 1]];
        location[location_index].table = pml;
        location[location_index++].index = indices[i - 1];

        if (entry & ARM64_MMU_VALID)
        {
            void *page = (void *) PML_EXTRACT_ADDRESS(entry);
            pml = (PML *) PHYS_TO_VIRT(page);
        }
        else
        {
            return false;
        }
    }

    location[location_index].table = pml;
    location[location_index++].index = indices[0];

    *entry_ptr = &pml->entries[indices[0]];

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

    addr_space->arch_mmu.top_pt = new_pml;
    return 0;
}

PML *paging_fork_pml(PML *pml, int entry, struct mm_address_space *as)
{
    uint64_t old_address = PML_EXTRACT_ADDRESS(pml->entries[entry]);
    uint64_t perms = PML_EXTRACT_PERMS(pml->entries[entry]);

    void *new_pt = alloc_pt();
    if (!new_pt)
        return nullptr;

    increment_vm_stat(as, page_tables_size, PAGE_SIZE);

    pml->entries[entry] = (uint64_t) new_pt | perms;
    PML *new_pml = (PML *) PHYS_TO_VIRT(new_pt);
    PML *old_pml = (PML *) PHYS_TO_VIRT(old_address);
    memcpy(new_pml, old_pml, sizeof(PML));
    return new_pml;
}

int paging_fork_tables(struct mm_address_space *addr_space)
{
    struct page *page = alloc_page(0);
    if (!page)
        return -1;

    __atomic_add_fetch(&allocated_page_tables, 1, __ATOMIC_RELAXED);
    increment_vm_stat(addr_space, page_tables_size, PAGE_SIZE);

    unsigned long new_pml = pfn_to_paddr(page_to_pfn(page));
    PML *p = (PML *) PHYS_TO_VIRT(new_pml);
    PML *curr = (PML *) PHYS_TO_VIRT(get_current_page_tables());
    memcpy(p, curr, sizeof(PML));

    PML *mod_pml = (PML *) PHYS_TO_VIRT(new_pml);
    /* TODO: Destroy the page tables on failure */
    for (int i = 0; i < 256; i++)
    {
        if (mod_pml->entries[i] & ARM64_MMU_VALID)
        {
            PML *pml3 = (PML *) paging_fork_pml(mod_pml, i, addr_space);
            if (!pml3)
            {
                return -1;
            }

            for (int j = 0; j < PAGE_TABLE_ENTRIES; j++)
            {
                if (pml3->entries[j] & ARM64_MMU_VALID)
                {
                    PML *pml2 = (PML *) paging_fork_pml((PML *) pml3, j, addr_space);
                    if (!pml2)
                    {
                        return -1;
                    }

                    for (int k = 0; k < PAGE_TABLE_ENTRIES; k++)
                    {
                        if (pml2->entries[k] & ARM64_MMU_VALID &&
                            !pt_entry_is_huge(pml2->entries[k]))
                        {
                            PML *pml1 = (PML *) paging_fork_pml((PML *) pml2, k, addr_space);
                            if (!pml1)
                            {
                                return -1;
                            }
                        }
                    }
                }
            }
        }
    }

    addr_space->arch_mmu.top_pt = (void *) new_pml;
    return 0;
}

void paging_load_top_pt_kernel(PML *pml)
{
    msr("ttbr1_el1", pml);
    isb();
    dsb();
}

void paging_load_top_pt(PML *pml)
{
    msr("ttbr0_el1", pml);
    __native_tlb_invalidate_all();
    isb();
    dsb();
}

bool arm64_get_pt_entry(void *addr, uint64_t **entry_ptr, bool may_create_path,
                        struct mm_address_space *mm)
{
    unsigned long virt = (unsigned long) addr;
    unsigned int indices[arm64_max_paging_levels];

    addr_to_indices(virt, indices);

    PML *pml = (PML *) ((unsigned long) mm->arch_mmu.top_pt + PHYS_BASE);
    unsigned int i;

    for (i = arm64_paging_levels; i != 1; i--)
    {
        uint64_t entry = pml->entries[indices[i - 1]];
        if (entry & ARM64_MMU_VALID)
        {
            if (entry & ARM64_MMU_TABLE)
            {
                void *page = (void *) PML_EXTRACT_ADDRESS(entry);
                pml = (PML *) PHYS_TO_VIRT(page);
            }
            else
            {
                // Block entry!
                break;
            }
        }
        else
        {
            if (!may_create_path)
                return false;

            PML *pt = alloc_pt();

            if (!pt)
                return false;
            increment_vm_stat(mm, page_tables_size, PAGE_SIZE);

            pml->entries[indices[i - 1]] = arm64_make_pt_entry_page_table(pt);

            pml = (PML *) PHYS_TO_VIRT(pt);
        }
    }

    *entry_ptr = &pml->entries[indices[i - 1]];

    return true;
}

bool paging_write_protect(void *addr, struct mm_address_space *mm)
{
    uint64_t *ptentry;
    if (!arm64_get_pt_entry(addr, &ptentry, false, mm))
        return false;

    *ptentry = *ptentry | ARM64_MMU_READ_ONLY;

    return true;
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

    paging_load_top_pt_kernel(pml);

    // TODO(pedro): Disable the bottom half translation properly
    auto zero_page = page_to_phys(vm_get_zero_page());
    paging_load_top_pt((PML *) zero_page);
}

unsigned long total_shootdowns = 0;

/**
 * @brief Directly maps a page into the paging tables.
 *
 * @param as The target address space.
 * @param virt The virtual address.
 * @param phys The physical address of the page.
 * @param prot Desired protection flags.
 * @return NULL if out of memory, else virt.
 */
void *vm_map_page(struct mm_address_space *as, uint64_t virt, uint64_t phys, uint64_t prot)
{
    return paging_map_phys_to_virt(as, virt, phys, prot);
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

unsigned long get_mapping_info(void *addr)
{
    struct mm_address_space *as = &kernel_address_space;
    if ((unsigned long) addr < VM_HIGHER_HALF)
        as = get_current_address_space();

    return __get_mapping_info(addr, as);
}

unsigned long __get_mapping_info(void *addr, struct mm_address_space *as)
{
    unsigned long *ppt_entry;
    if (!arm64_get_pt_entry(addr, &ppt_entry, false, as))
        return PAGE_NOT_PRESENT;

    unsigned long pt_entry = *ppt_entry;

    unsigned long ret = 0;

    if (pt_entry & ARM64_MMU_VALID)
        ret |= PAGE_PRESENT;
    else
    {
        return PAGE_NOT_PRESENT;
    }

    if (pt_entry & ARM64_MMU_EL0)
        ret |= PAGE_USER;

    bool non_executable = ret & PAGE_USER ? pt_entry & ARM64_MMU_XN : pt_entry & ARM64_MMU_PXN;

    if (!(pt_entry & ARM64_MMU_READ_ONLY))
        ret |= PAGE_WRITABLE;
    if (!non_executable)
        ret |= PAGE_EXECUTABLE;
    if (!(pt_entry & ARM64_MMU_READ_ONLY))
        ret |= PAGE_DIRTY;
    if (pt_entry & ARM64_MMU_AF)
        ret |= PAGE_ACCESSED;
    if (!(pt_entry & ARM64_MMU_nG))
        ret |= PAGE_GLOBAL;

    ret |= PML_EXTRACT_ADDRESS(pt_entry);

    return ret;
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
    mm->arch_mmu.top_pt = page_to_phys(alloc_page(0));
}

/**
 * @brief Directly mprotect a page in the paging tables.
 * Called by core MM code and should not be used outside of it.
 * This function handles any edge cases like trying to re-apply write perms on
 * a write-protected page.
 *
 * @param as The target address space.
 * @param addr The virtual address of the page.
 * @param old_prots The old protection flags.
 * @param new_prots The new protection flags.
 */
void vm_mmu_mprotect_page(struct mm_address_space *as, void *addr, int old_prots, int new_prots)
{
    uint64_t *ptentry;
    if (!arm64_get_pt_entry(addr, &ptentry, false, as))
        return;

    if (!*ptentry)
        return;

    /* Make sure we don't accidentally mark a page as writable when
     * it's write-protected and we're changing some other bits.
     * For example: mprotect(PROT_EXEC) on a COW'd supposedly writable
     * page would try to re-apply the writable permission.
     */

    /* In this function, we use the old_prots parameter to know whether it was a write-protected
     * page.
     */
    bool is_wp_page = *ptentry & ARM64_MMU_READ_ONLY && old_prots & VM_WRITE;

    if (is_wp_page)
    {
        new_prots &= ~VM_WRITE;
        // printk("NOT VM_WRITING\n");
    }

    // printk("new prots: %x\n", new_prots);

    unsigned long paddr = PML_EXTRACT_ADDRESS(*ptentry);
    uint64_t page_prots = vm_prots_to_mmu(new_prots);

    arm64_set_pte(addr, ptentry, paddr | page_prots);
}

/**
 * @brief Directly mprotect a range in the paging tables.
 *
 * This function handles any edge cases like trying to re-apply write perms on
 * a write-protected page. It also invalidates the TLB.
 *
 * @param as The target address space.
 * @param address The virtual address of the range.
 * @param nr_pgs Number of pages in the range
 * @param old_prots The old protection flags.
 * @param new_prots The new protection flags.
 */
void vm_do_mmu_mprotect(struct mm_address_space *as, void *address, size_t nr_pgs, int old_prots,
                        int new_prots)
{
    for (size_t i = 0; i < nr_pgs; i++)
    {
        vm_mmu_mprotect_page(as, address, old_prots, new_prots);

        address = (void *) ((unsigned long) address + PAGE_SIZE);
    }
}

class page_table_iterator
{
private:
    unsigned long curr_addr_;
    size_t length_;

public:
    struct mm_address_space *as_;

#ifdef CONFIG_PT_ITERATOR_HAVE_DEBUG
    bool debug;
#endif

    page_table_iterator(unsigned long virt, size_t len, struct mm_address_space *as)
        : curr_addr_{virt}, length_{len}, as_{as}

#ifdef CONFIG_PT_ITERATOR_HAVE_DEBUG
          ,
          debug{false}
#endif

    {
    }

    size_t length() const
    {
        return length_;
    }

    unsigned long curr_addr() const
    {
        return curr_addr_;
    }

    void adjust_length(size_t size)
    {
        if (size > length_)
        {
            length_ = 0;
            curr_addr_ += length_;
        }
        else
        {
            length_ -= size;
            curr_addr_ += size;
        }
    }
};

struct tlb_invalidation_tracker
{
    unsigned long virt_start{};
    unsigned long virt_end{};
    bool is_started{}, is_flushed{};

    explicit tlb_invalidation_tracker() = default;

    void invalidate_tracker()
    {
        virt_start = 0xDEADDAD;
        virt_end = 0xB0;
        is_started = false;
        is_flushed = false;
    }

    void flush()
    {
        if (!is_started)
            return;

        vm_invalidate_range(virt_start, (virt_end - virt_start) >> PAGE_SHIFT);
        invalidate_tracker();
    }

    constexpr void init(unsigned long vaddr, size_t size)
    {
        is_started = true;
        virt_start = vaddr;
        virt_end = vaddr + size;
        is_flushed = false;
    }

    void add_page(unsigned long vaddr, size_t size)
    {
        /* If we've already started on a run of pages and this one is contiguous, just set the tail
         */
        if (is_started && virt_end == vaddr)
        {
            virt_end = vaddr + size;
        }
        else
        {
            /* Else, try flushing if is_started == true and restart the page run */
            flush();
            init(vaddr, size);
        }
    }

    ~tlb_invalidation_tracker()
    {
        if (is_started && !is_flushed)
            flush();
    }
};

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
    // Every level is a huge page level in ARM64
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

#define MMU_UNMAP_CAN_FREE_PML 1
#define MMU_UNMAP_OK           0

static int arm64_mmu_unmap(PML *table, unsigned int pt_level, page_table_iterator &it)
{
    unsigned int index = addr_get_index(it.curr_addr(), pt_level);

    /* Get the size that each entry represents here */
    auto entry_size = level_to_entry_size(pt_level);

    tlb_invalidation_tracker invd_tracker;
    unsigned int i;

#ifdef CONFIG_PT_ITERATOR_HAVE_DEBUG
    if (it.debug)
    {
        printk("level %u - index %x\n", pt_level, index);
    }
#endif

    for (i = index; i < PAGE_TABLE_ENTRIES && it.length(); i++)
    {
        auto &pt_entry = table->entries[i];
        bool is_pte_empty = pte_empty(pt_entry);

        if (is_pte_empty)
        {

#ifdef CONFIG_ARM64_MMU_UNMAP_DEBUG
            if (it.debug)
                printk("not present @ level %u\nentry size %lu\nlength %lu\n", pt_level, entry_size,
                       it.length());
#endif
            auto to_skip = entry_size - (it.curr_addr() & (entry_size - 1));

#ifdef CONFIG_PT_ITERATOR_HAVE_DEBUG
            if (it.debug)
            {
                printk("[level %u]: Skipping from %lx to %lx\n", pt_level, it.curr_addr(),
                       it.curr_addr() + to_skip);
            }
#endif

            it.adjust_length(to_skip);
            continue;
        }

        bool is_huge_page = is_huge_page_level(pt_level) && pt_entry_is_huge(pt_entry);

        if (pt_level == PT_LEVEL || is_huge_page)
        {
            /* TODO: Handle huge page splitting */

#ifdef CONFIG_PT_ITERATOR_HAVE_DEBUG
            if (it.debug)
                printk("Unmapping %lx\n", it.curr_addr());
#endif

            unsigned long val = 0;
            __atomic_exchange(&pt_entry, &val, &val, __ATOMIC_RELEASE);

            if (val & ARM64_MMU_AF)
            {
                invd_tracker.add_page(it.curr_addr(), entry_size);
            }

            it.adjust_length(entry_size);
            decrement_vm_stat(it.as_, resident_set_size, entry_size);
        }
        else
        {
            assert((pt_entry & ARM64_MMU_VALID) != 0);
            PML *next_table = (PML *) PHYS_TO_VIRT(PML_EXTRACT_ADDRESS(pt_entry));
            int st = arm64_mmu_unmap(next_table, pt_level - 1, it);

            if (st == MMU_UNMAP_CAN_FREE_PML)
            {
                auto page = phys_to_page(PML_EXTRACT_ADDRESS(pt_entry));

                pt_entry = 0;

                COMPILER_BARRIER();

                free_page(page);
                __atomic_sub_fetch(&allocated_page_tables, 1, __ATOMIC_RELAXED);
                decrement_vm_stat(it.as_, page_tables_size, PAGE_SIZE);
            }
        }
    }

    /* We can know that the table is 100% empty if we ran through the table */
    bool unmapped_whole_table = index == 0 && i == PAGE_TABLE_ENTRIES;

    /* Don't bother to free the PML or even check if it's empty if we're the top paging structure */
    if (pt_level != arm64_paging_levels - 1 && (unmapped_whole_table || pml_is_empty(table)))
    {
        return MMU_UNMAP_CAN_FREE_PML;
    }

#if 0
    printk("nr entries %lu\n", nr_entries);

    printk("unmapping %lu\n", it.length());
#endif

    return MMU_UNMAP_OK;
}

int vm_mmu_unmap(struct mm_address_space *as, void *addr, size_t pages)
{
    unsigned long virt = (unsigned long) addr;
    size_t size = pages << PAGE_SHIFT;

    page_table_iterator it{virt, size, as};

    PML *first_level = (PML *) PHYS_TO_VIRT(as->arch_mmu.top_pt);

    arm64_mmu_unmap(first_level, arm64_paging_levels - 1, it);

    assert(it.length() == 0);

    return 0;
}

static inline bool is_higher_half(unsigned long address)
{
    return address >= VM_HIGHER_HALF;
}

PER_CPU_VAR(unsigned long tlb_nr_invals) = 0;
PER_CPU_VAR(unsigned long nr_tlb_shootdowns) = 0;

/**
 * @brief Invalidates a memory range.
 *
 * @param addr The start of the memory range.
 * @param pages The size of the memory range, in pages.
 * @param mm The target address space.
 */
void mmu_invalidate_range(unsigned long addr, size_t pages, mm_address_space *mm)
{
    dsb();

    while (pages--)
    {
        __native_tlb_invalidate_page((void *) addr);
        addr += PAGE_SIZE;
    }

    dsb();
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

    for (const auto pte : pt->entries)
    {
        if (pte_empty(pte))
            continue;

        if (!(pte & ARM64_MMU_EL0))
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

#define DEBUG_PRINT_MAPPING 0

/**
 * @brief Map a specific number of pages onto a virtual address.
 * Should only be used by MM code since it does not touch vm_regions, only
 * MMU page tables.
 *
 * @param as   The target address space.
 * @param virt The virtual address.
 * @param phys The start of the physical range.
 * @param size The size of the mapping, in bytes.
 * @param flags The permissions on the mapping.
 *
 * @return NULL on error, virt on success.
 */
void *__map_pages_to_vaddr(struct mm_address_space *as, void *virt, void *phys, size_t size,
                           size_t flags)
{
    size_t pages = vm_size_to_pages(size);

#if DEBUG_PRINT_MAPPING
    printk("__map_pages_to_vaddr: %p (phys %p) - %lx\n", virt, phys, (unsigned long) virt + size);
#endif
    void *ptr = virt;
    for (uintptr_t virt = (uintptr_t) ptr, _phys = (uintptr_t) phys, i = 0; i < pages;
         virt += PAGE_SIZE, _phys += PAGE_SIZE, ++i)
    {
        if (!vm_map_page(as, virt, _phys, flags))
            return nullptr;
    }

    return ptr;
}
