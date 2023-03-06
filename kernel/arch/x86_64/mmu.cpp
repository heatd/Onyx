/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <cpuid.h>
#include <stdbool.h>
#include <stdio.h>

#include <onyx/cpu.h>
#include <onyx/page.h>
#include <onyx/paging.h>
#include <onyx/panic.h>
#include <onyx/process.h>
#include <onyx/smp.h>
#include <onyx/vm.h>
#include <onyx/x86/pat.h>

static const unsigned int x86_paging_levels = 4;
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
#define X86_PAGING_NX           (1UL << 63)

#define X86_PAGING_PROT_BITS ((PAGE_SIZE - 1) | X86_PAGING_NX)

#define X86_PAGING_FLAGS_TO_SAVE_ON_MPROTECT                                       \
    (X86_PAGING_GLOBAL | X86_PAGING_HUGE | X86_PAGING_USER | X86_PAGING_ACCESSED | \
     X86_PAGING_DIRTY | X86_PAGING_WRITETHROUGH | X86_PAGING_PCD | X86_PAGING_PAT)

void *paging_map_phys_to_virt(struct mm_address_space *as, uint64_t virt, uint64_t phys,
                              uint64_t prot);

static inline void __native_tlb_invalidate_page(void *addr)
{
    __asm__ __volatile__("invlpg (%0)" : : "b"(addr) : "memory");
}

bool x86_pte_empty(uint64_t pte)
{
    return pte == 0;
}

bool x86_get_pt_entry(void *addr, uint64_t **entry_ptr, struct mm_address_space *mm);

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

typedef struct
{
    uint64_t offsetFromPage : 12;
    uint64_t pt : 9;
    uint64_t pd : 9;
    uint64_t pdpt : 9;
    uint64_t pml4 : 9;
    uint64_t rest : 16;
} decomposed_addr_t;

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

PML *boot_pml4;

PML *get_current_pml4(void)
{
    struct process *p = get_current_process();
    if (!p)
        return boot_pml4;
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
    return __virtual2phys(get_current_pml4(), ptr);
}

extern PML pdptphysical_map;
static PML pdphysical_map[4] __attribute__((aligned(PAGE_SIZE)));

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
    kernel_address_space.arch_mmu.cr3 = get_current_pml4();

    /* Map two pages so memory that spans both pages can get accessed */
    paging_map_phys_to_virt(&kernel_address_space, placement_mappings_start, phys,
                            VM_READ | VM_WRITE);
    paging_map_phys_to_virt(&kernel_address_space, placement_mappings_start + PAGE_SIZE,
                            phys + PAGE_SIZE, VM_READ | VM_WRITE);
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

    PML *pml = (PML *) PA2VA(boot_pml4);

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

NO_ASAN
void paging_init(void)
{
    /* Get the current PML and store it */
    __asm__ __volatile__("movq %%cr3, %%rax\t\nmovq %%rax, %0" : "=r"(boot_pml4)::"rax", "memory");
    kernel_address_space.arch_mmu.cr3 = boot_pml4;

    /* Bootstrap the first 4GB */
    uintptr_t virt = PHYS_BASE;
    PML *pml3 = (PML *) ((unsigned long) &pdptphysical_map + get_kernel_phys_offset());
    PML *pml4 =
        (PML *) ((unsigned long) boot_pml4 + KERNEL_VIRTUAL_BASE - get_kernel_phys_offset());
    unsigned int indices[x86_max_paging_levels];
    x86_addr_to_indices(virt, indices);

    pml4->entries[indices[x86_paging_levels - 1]] = make_pml4e((uint64_t) pml3, 0, 0, 0, 0, 1, 1);
    auto pdphysmap_phys = VA2PA(&pdphysical_map);

    pml3 = (PML *) ((unsigned long) &pdptphysical_map + KERNEL_VIRTUAL_BASE);
    for (int i = 0; i < 4; i++)
    {
        pml3->entries[i] = make_pml3e(pdphysmap_phys + 0x1000 * i, 0, 0, 1, 0, 0, 0, 1, 1);

        for (size_t j = 0; j < 512; j++)
        {
            uintptr_t p = (i << HUGE1GB_SHIFT) + (j << LARGE2MB_SHIFT);

            pdphysical_map[i].entries[j] = p | X86_PAGING_WRITE | X86_PAGING_PRESENT |
                                           X86_PAGING_GLOBAL | X86_PAGING_NX | X86_PAGING_HUGE;
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
    decomposed_addr_t decAddr;
    memcpy(&decAddr, &virt, sizeof(decomposed_addr_t));
    PML *bpml = (PML *) PA2VA(boot_pml4);
    uint64_t *entry = &bpml->entries[decAddr.pml4];
    PML *pml3 = (PML *) ((unsigned long) &pdptphysical_map + get_kernel_phys_offset());

    *entry = make_pml4e((uint64_t) pml3, 0, 0, 0, 0, 1, 1);

    if (is_1gb_supported)
    {
        for (size_t i = 0; i < 512; i++)
        {
            entry = &pml3->entries[i];
            *entry = make_pml3e(i * 0x40000000, 1, 0, 1, 0, 0, 0, 1, 1);
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
                uintptr_t p = i * 512 * 0x200000 + j * 0x200000;

                pd->entries[j] = p | X86_PAGING_WRITE | X86_PAGING_PRESENT | X86_PAGING_GLOBAL |
                                 X86_PAGING_NX | X86_PAGING_HUGE;
            }

            entry++;
        }

        memcpy(pml3, &new_pml3, sizeof(PML));
    }

    for (size_t i = 0; i < 512; i++)
        __native_tlb_invalidate_page((void *) (virt + i * 0x40000000));
}

void *paging_map_phys_to_virt(struct mm_address_space *as, uint64_t virt, uint64_t phys,
                              uint64_t prot)
{
    bool user = prot & VM_USER;

    if (!as)
    {
        as = user ? get_current_address_space() : &kernel_address_space;
        assert(as != nullptr);
    }

    scoped_lock g{as->page_table_lock};

    unsigned int indices[x86_max_paging_levels];

    /* Note: page table flags are different from page perms because a page table's
     * permissions apply throughout the whole table.
     * Because of that, the PT's flags are Present | Write | (possible User)
     */
    uint64_t page_table_flags =
        X86_PAGING_PRESENT | X86_PAGING_WRITE | (user ? X86_PAGING_USER : 0);

    x86_addr_to_indices(virt, indices);

    PML *pml = (PML *) PHYS_TO_VIRT(as->arch_mmu.cr3);

    for (unsigned int i = x86_paging_levels; i != 1; i--)
    {
        uint64_t entry = pml->entries[indices[i - 1]];
        if (entry & X86_PAGING_PRESENT)
        {
            void *page = (void *) PML_EXTRACT_ADDRESS(entry);
            pml = (PML *) PHYS_TO_VIRT(page);
        }
        else
        {
            assert(entry == 0);
            void *page = alloc_pt();
            if (!page)
                return nullptr;

            increment_vm_stat(as, page_tables_size, PAGE_SIZE);
            pml->entries[indices[i - 1]] = (uint64_t) page | page_table_flags;
            pml = (PML *) PHYS_TO_VIRT(page);
        }
    }

    bool noexec = !(prot & VM_EXEC);
    bool global = prot & VM_USER ? false : true;
    user = prot & VM_USER ? true : false;
    bool write = prot & VM_WRITE ? true : false;
    bool readable = prot & (VM_READ | VM_WRITE) || !noexec;
    unsigned int cache_type = vm_prot_to_cache_type(prot);
    uint8_t caching_bits = cache_to_paging_bits(cache_type);

    uint64_t page_prots = (noexec ? X86_PAGING_NX : 0) | (global ? X86_PAGING_GLOBAL : 0) |
                          (user ? X86_PAGING_USER : 0) | (write ? X86_PAGING_WRITE : 0) |
                          X86_CACHING_BITS(caching_bits) | (readable ? X86_PAGING_PRESENT : 0);

    if (prot & VM_DONT_MAP_OVER && pml->entries[indices[0]] & X86_PAGING_PRESENT)
        return (void *) virt;

    uint64_t old = pml->entries[indices[0]];

    pml->entries[indices[0]] = phys | page_prots;

    if (x86_pte_empty(old))
    {
        increment_vm_stat(as, resident_set_size, PAGE_SIZE);
    }

    return (void *) virt;
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

struct pt_location
{
    PML *table;
    unsigned int index;
};

bool x86_get_pt_entry_with_ptables(void *addr, uint64_t **entry_ptr, struct mm_address_space *mm,
                                   struct pt_location location[4])
{
    unsigned long virt = (unsigned long) addr;
    unsigned int indices[x86_max_paging_levels];

    for (unsigned int i = 0; i < x86_paging_levels; i++)
    {
        indices[i] = (virt >> 12) >> (i * 9) & 0x1ff;
        location[4 - 1 - i].index = indices[i];
    }

    PML *pml = (PML *) ((unsigned long) mm->arch_mmu.cr3 + PHYS_BASE);
    unsigned int location_index = 0;

    for (unsigned int i = x86_paging_levels; i != 1; i--)
    {
        uint64_t entry = pml->entries[indices[i - 1]];
        location[location_index].table = pml;
        location[location_index++].index = indices[i - 1];

        if (entry & X86_PAGING_PRESENT)
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
    scoped_mutex g{original->vm_lock};
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

PML *paging_fork_pml(PML *pml, int entry, struct mm_address_space *as)
{
    uint64_t old_address = PML_EXTRACT_ADDRESS(pml->entries[entry]);
    uint64_t perms = pml->entries[entry] & 0xF000000000000FFF;

    void *new_pt = alloc_pt();
    if (!new_pt)
        return NULL;

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

    scoped_lock g{get_current_address_space()->page_table_lock};

    unsigned long new_pml = pfn_to_paddr(page_to_pfn(page));
    PML *p = (PML *) PHYS_TO_VIRT(new_pml);
    PML *curr = (PML *) PHYS_TO_VIRT(get_current_pml4());
    memcpy(p, curr, sizeof(PML));

    PML *mod_pml = (PML *) PHYS_TO_VIRT(new_pml);
    /* TODO: Destroy the page tables on failure */
    for (int i = 0; i < 256; i++)
    {
        if (mod_pml->entries[i] & X86_PAGING_PRESENT)
        {
            PML *pml3 = (PML *) paging_fork_pml(mod_pml, i, addr_space);
            if (!pml3)
            {
                return -1;
            }

            for (int j = 0; j < PAGE_TABLE_ENTRIES; j++)
            {
                if (pml3->entries[j] & X86_PAGING_PRESENT)
                {
                    PML *pml2 = (PML *) paging_fork_pml((PML *) pml3, j, addr_space);
                    if (!pml2)
                    {
                        return -1;
                    }

                    for (int k = 0; k < PAGE_TABLE_ENTRIES; k++)
                    {
                        if (pml2->entries[k] & X86_PAGING_PRESENT &&
                            !(pml2->entries[k] & X86_PAGING_HUGE))
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

    addr_space->arch_mmu.cr3 = (void *) new_pml;
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

bool x86_get_pt_entry(void *addr, uint64_t **entry_ptr, struct mm_address_space *mm)
{
    unsigned long virt = (unsigned long) addr;
    unsigned int indices[x86_max_paging_levels];

    x86_addr_to_indices(virt, indices);

    PML *pml = (PML *) ((unsigned long) mm->arch_mmu.cr3 + PHYS_BASE);

    for (unsigned int i = x86_paging_levels; i != 1; i--)
    {
        uint64_t entry = pml->entries[indices[i - 1]];
        if (entry & X86_PAGING_PRESENT)
        {
            void *page = (void *) PML_EXTRACT_ADDRESS(entry);
            pml = (PML *) PHYS_TO_VIRT(page);
        }
        else
        {
            return false;
        }
    }

    *entry_ptr = &pml->entries[indices[0]];

    return true;
}

bool __paging_change_perms(struct mm_address_space *mm, void *addr, int prot)
{
    scoped_lock g{mm->page_table_lock};

    uint64_t *entry;
    if (!x86_get_pt_entry(addr, &entry, mm))
    {
        return false;
    }

    uint64_t pt_entry = *entry;
    uint64_t perms = pt_entry & X86_PAGING_FLAGS_TO_SAVE_ON_MPROTECT;
    uint64_t page = PML_EXTRACT_ADDRESS(pt_entry);

    if (!(prot & VM_EXEC))
        perms |= X86_PAGING_NX;
    if (prot & VM_WRITE)
        perms |= X86_PAGING_WRITE;
    if (prot & VM_READ)
        perms |= X86_PAGING_PRESENT;
    *entry = perms | page;

    return true;
}

bool paging_change_perms(void *addr, int prot)
{
    struct mm_address_space *as = &kernel_address_space;
    if ((unsigned long) addr < VM_HIGHER_HALF)
        as = get_current_address_space();

    return __paging_change_perms(as, addr, prot);
}

bool paging_write_protect(void *addr, struct mm_address_space *mm)
{
    scoped_lock g{mm->page_table_lock};

    uint64_t *ptentry;
    if (!x86_get_pt_entry(addr, &ptentry, mm))
        return false;

    *ptentry = *ptentry & ~X86_PAGING_WRITE;

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

void paging_walk(void *addr)
{
    decomposed_addr_t dec;
    memcpy(&dec, &addr, sizeof(decomposed_addr_t));
    PML *pml4 = (PML *) ((uint64_t) get_current_pml4() + PHYS_BASE);

    uint64_t *entry = &pml4->entries[dec.pml4];
    if (*entry == 0)
    {
        printk("isn't mapped(PML %p)\n", pml4);
        return;
    }
    PML *pml3 = (PML *) ((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
    entry = &pml3->entries[dec.pdpt];
    if (*entry == 0)
    {
        printk("isn't mapped(PML %p)\n", pml3);
        return;
    }
    PML *pml2 = (PML *) ((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
    entry = &pml2->entries[dec.pd];
    if (*entry == 0)
    {
        printk("isn't mapped(PML %p)\n", pml2);
        return;
    }
    PML *pml1 = (PML *) ((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
    entry = &pml1->entries[dec.pt];
    if (*entry == 0)
    {
        printk("isn't mapped(PML %p)\n", pml1);
        return;
    }
    uint32_t perms = *entry & 0xF00000000000FFF;
    uint64_t page = PML_EXTRACT_ADDRESS(*entry);
    printk("Perms: %08x\nPage: %016lx\n", perms, page);
}

extern char _text_start;
extern char _text_end;
extern char _data_start;
extern char _data_end;
extern struct mm_address_space kernel_address_space;

void paging_protect_kernel(void)
{
    PML *original_pml = boot_pml4;
    PML *pml = alloc_pt();
    assert(pml != nullptr);
    boot_pml4 = pml;

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

    __asm__ __volatile__("movq %0, %%cr3" ::"r"(pml));
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
    mm->arch_mmu.cr3 = get_current_pml4();
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
    scoped_lock g{as->page_table_lock};

    uint64_t *ptentry;
    if (!x86_get_pt_entry(addr, &ptentry, as))
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
    bool is_wp_page = !(*ptentry & X86_PAGING_WRITE) && old_prots & VM_WRITE;

    if (is_wp_page)
    {
        new_prots &= ~VM_WRITE;
        // printk("NOT VM_WRITING\n");
    }

    // printk("new prots: %x\n", new_prots);

    unsigned long paddr = PML_EXTRACT_ADDRESS(*ptentry);
    bool noexec = !(new_prots & VM_EXEC);
    bool global = new_prots & VM_USER ? false : true;
    bool user = new_prots & VM_USER ? true : false;
    bool write = new_prots & VM_WRITE ? true : false;
    bool readable = new_prots & (VM_READ | VM_WRITE) || !noexec;

    unsigned int cache_type = vm_prot_to_cache_type(new_prots);
    uint8_t caching_bits = cache_to_paging_bits(cache_type);

    uint64_t page_prots = (noexec ? X86_PAGING_NX : 0) | (global ? X86_PAGING_GLOBAL : 0) |
                          (user ? X86_PAGING_USER : 0) | (write ? X86_PAGING_WRITE : 0) |
                          X86_CACHING_BITS(caching_bits) | (readable ? X86_PAGING_PRESENT : 0);
    *ptentry = paddr | page_prots;
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
    unsigned long virt_start;
    unsigned long virt_end;
    bool is_started, is_flushed;

    explicit tlb_invalidation_tracker() : virt_start{}, virt_end{}, is_started{}, is_flushed{}
    {
    }

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
        /* If we've already started on a run of pages and this one is contiguous, just set the
         * tail
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

enum x86_page_table_levels : unsigned int
{
    PT_LEVEL,
    PD_LEVEL,
    PDPT_LEVEL,
    PML4_LEVEL,
    PML5_LEVEL
};

bool x86_is_pml5_enabled()
{
    return x86_paging_levels == 5;
}

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

#define MMU_UNMAP_CAN_FREE_PML 1
#define MMU_UNMAP_OK           0

static int x86_mmu_unmap(PML *table, unsigned int pt_level, page_table_iterator &it)
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
        bool pte_empty = x86_pte_empty(pt_entry);

        if (pte_empty)
        {

#ifdef CONFIG_X86_MMU_UNMAP_DEBUG
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

        bool is_huge_page = is_huge_page_level(pt_level) && pt_entry & X86_PAGING_HUGE;

        if (pt_level == PT_LEVEL || is_huge_page)
        {
            /* TODO: Handle huge page splitting */

#ifdef CONFIG_PT_ITERATOR_HAVE_DEBUG
            if (it.debug)
                printk("Unmapping %lx\n", it.curr_addr());
#endif

            unsigned long val = 0;
            __atomic_exchange(&pt_entry, &val, &val, __ATOMIC_RELEASE);

            if (val & X86_PAGING_ACCESSED)
            {
                invd_tracker.add_page(it.curr_addr(), entry_size);
            }

            it.adjust_length(entry_size);
            decrement_vm_stat(it.as_, resident_set_size, entry_size);
        }
        else
        {
            assert((pt_entry & X86_PAGING_PRESENT) != 0);
            PML *next_table = (PML *) PHYS_TO_VIRT(PML_EXTRACT_ADDRESS(pt_entry));
            int st = x86_mmu_unmap(next_table, pt_level - 1, it);

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

    /* Don't bother to free the PML or even check if it's empty if we're the top paging
     * structure */
    if (pt_level != x86_paging_levels - 1 && (unmapped_whole_table || pml_is_empty(table)))
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
    scoped_lock g{as->page_table_lock};

    page_table_iterator it{virt, size, as};

    PML *first_level = (PML *) PHYS_TO_VIRT(as->arch_mmu.cr3);

    x86_mmu_unmap(first_level, x86_paging_levels - 1, it);

    assert(it.length() == 0);

    return 0;
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
    auto top = (PML *) PHYS_TO_VIRT(get_current_pml4());
    top->entries[indices1[x86_paging_levels - 1]] = top->entries[indices0[x86_paging_levels - 1]];
    top->entries[indices0[x86_paging_levels - 1]] = 0;
    __native_tlb_invalidate_all();
}

unsigned long get_mapping_info(void *addr)
{
    struct mm_address_space *as = &kernel_address_space;
    if ((unsigned long) addr < VM_HIGHER_HALF)
        as = get_current_address_space();

    return __get_mapping_info(addr, as);
}

static inline unsigned long pte_to_mapping_info(unsigned long pt_entry, bool hugepage,
                                                unsigned long offset)
{
    unsigned long ret = 0;
    if (pt_entry & X86_PAGING_PRESENT)
        ret |= PAGE_PRESENT;
    else
    {
        return PAGE_NOT_PRESENT;
    }

    if (pt_entry & X86_PAGING_USER)
        ret |= PAGE_USER;
    if (pt_entry & X86_PAGING_WRITE)
        ret |= PAGE_WRITABLE;
    if (!(pt_entry & X86_PAGING_NX))
        ret |= PAGE_EXECUTABLE;
    if (pt_entry & X86_PAGING_DIRTY)
        ret |= PAGE_DIRTY;
    if (pt_entry & X86_PAGING_ACCESSED)
        ret |= PAGE_ACCESSED;
    if (pt_entry & X86_PAGING_GLOBAL)
        ret |= PAGE_GLOBAL;
    if (hugepage)
        ret |= PAGE_HUGE;

    ret |= PML_EXTRACT_ADDRESS(pt_entry);
    ret |= offset;

    return ret;
}

unsigned long __get_mapping_info(void *addr, struct mm_address_space *as)
{
    // TODO: Should we lock here? May be slow.
    const unsigned long virt = (unsigned long) addr;
    unsigned int indices[x86_max_paging_levels];

    x86_addr_to_indices(virt, indices);

    PML *pml = (PML *) PHYS_TO_VIRT(as->arch_mmu.cr3);
    for (unsigned i = x86_paging_levels; i != 1; i--)
    {
        unsigned long entry = pml->entries[indices[i - 1]];
        void *page = (void *) PML_EXTRACT_ADDRESS(entry);
        if (entry & X86_PAGING_PRESENT)
        {
            if (entry & X86_PAGING_HUGE &&
                (i == x86_paging_levels - 1 || i == x86_paging_levels - 2))
            {
                // Calculate the offset inside the huge page by getting the size of each entry at
                // this level and then masking the virtual address with it. We then chop off the
                // PAGE_SIZE bits.
                auto entry_size = level_to_entry_size(i - 1);
                const auto offset = virt & (entry_size - 1) & -PAGE_SIZE;
                return pte_to_mapping_info(entry, true, offset);
            }

            pml = (PML *) PHYS_TO_VIRT(page);
        }
        else
        {
            return PAGE_NOT_PRESENT;
        }
    }

    return pte_to_mapping_info(pml->entries[indices[0]], false, 0);
}

#ifdef CONFIG_KASAN
#define KASAN_VIRTUAL 0xffffec0000000000

extern "C" char x86_stack_bottom[];
extern "C" char kasan_shadow_page_tables[];
static PML *shadow_pdpt, *shadow_pd, *shadow_pt;
static unsigned long *zero_shadow_map;

static inline char *kasan_get_ptr(unsigned long addr)
{
    return (char *) 0xdffffc0000000000 + (addr >> 3);
}

extern "C" NO_ASAN void x86_bootstrap_kasan()
{
    PML *pml4;
    PML *shadow_pts = (PML *) kasan_shadow_page_tables;
    __asm__ __volatile__("mov %%cr3, %0" : "=r"(pml4));
    unsigned int indices[x86_max_paging_levels];

    for (unsigned int i = 0; i < x86_paging_levels; i++)
    {
        indices[i] = (KASAN_VIRTUAL >> 12) >> (i * 9) & 0x1ff;
    }

    for (unsigned int i = 0; i < 32; i++)
    {
        pml4->entries[indices[x86_paging_levels - 1] + i] =
            VA2PA(shadow_pts) | X86_PAGING_PRESENT | X86_PAGING_GLOBAL | X86_PAGING_NX;
    }

    shadow_pdpt = shadow_pts;
    shadow_pd = ++shadow_pts;
    for (unsigned int i = 0; i < 512; i++)
    {
        shadow_pdpt->entries[i] =
            VA2PA(shadow_pd) | X86_PAGING_PRESENT | X86_PAGING_GLOBAL | X86_PAGING_NX;
    }

    shadow_pt = ++shadow_pts;

    for (unsigned int i = 0; i < 512; i++)
    {
        shadow_pd->entries[i] =
            VA2PA(shadow_pt) | X86_PAGING_PRESENT | X86_PAGING_GLOBAL | X86_PAGING_NX;
    }

    zero_shadow_map = (unsigned long *) ++shadow_pts;
    for (unsigned int i = 0; i < 512; i++)
    {
        shadow_pt->entries[i] =
            VA2PA(zero_shadow_map) | X86_PAGING_PRESENT | X86_PAGING_GLOBAL | X86_PAGING_NX;
    }

    // Map a page for the kernel stack, since the compiler generates code to write to it

    unsigned long cowable_pagetables[4];
    cowable_pagetables[0] = VA2PA(shadow_pdpt);
    cowable_pagetables[1] = VA2PA(shadow_pd);
    cowable_pagetables[2] = VA2PA(shadow_pt);
    cowable_pagetables[3] = VA2PA(zero_shadow_map);

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

    PML *pml = pml4;

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
        if ((unsigned long) page != cowable_pagetables[x86_paging_levels - i])
            continue;

        auto newpml = ++shadow_pts;

        // Copy the old page table
        __memcpy(newpml, pml, PAGE_SIZE);

        oldpml->entries[indices[i - 1]] = (uint64_t) VA2PA(newpml) | page_table_flags;
        pml = (PML *) newpml;
    }

    auto &entry = pml->entries[indices[0]];

    assert(entry & X86_PAGING_PRESENT);
    if (PML_EXTRACT_ADDRESS(entry) == cowable_pagetables[3])
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
    unsigned long cowable_pagetables[4];
    cowable_pagetables[0] = VA2PA(shadow_pdpt);
    cowable_pagetables[1] = VA2PA(shadow_pd);
    cowable_pagetables[2] = VA2PA(shadow_pt);
    cowable_pagetables[3] = VA2PA(zero_shadow_map);

    /* Note: page table flags are different from page perms because a page table's
     * permissions apply throughout the whole table.
     * Because of that, the PT's flags are Present | Write | (possible User)
     */
    uint64_t page_table_flags = X86_PAGING_PRESENT | X86_PAGING_WRITE;

    x86_addr_to_indices(virt, indices);

    PML *pml = (PML *) PHYS_TO_VIRT(get_current_pml4());

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
        if ((unsigned long) page != cowable_pagetables[x86_paging_levels - i])
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
    if (PML_EXTRACT_ADDRESS(entry) == cowable_pagetables[3])
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

#endif
