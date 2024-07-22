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

void *paging_map_phys_to_virt(struct mm_address_space *as, uint64_t virt, uint64_t phys,
                              uint64_t prot, struct vm_area_struct *vma);

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

bool riscv_get_pt_entry(void *addr, uint64_t **entry_ptr, bool may_create_path,
                        struct mm_address_space *mm);

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

void *paging_map_phys_to_virt(struct mm_address_space *as, uint64_t virt, uint64_t phys,
                              uint64_t prot, struct vm_area_struct *vma)
{
    bool user = prot & VM_USER;

    if (!as)
    {
        as = user ? get_current_address_space() : &kernel_address_space;
        assert(as != nullptr);
    }

    uint64_t *ptentry;

    if (!riscv_get_pt_entry((void *) virt, &ptentry, true, as))
        return nullptr;

    uint64_t page_prots = vm_prots_to_mmu(prot);
    bool special_mapping = phys == (u64) page_to_phys(vm_get_zero_page());

    if (special_mapping)
        page_prots |= RISCV_MMU_SPECIAL;

    if (prot & VM_DONT_MAP_OVER && *ptentry & RISCV_MMU_VALID)
        return (void *) virt;

    uint64_t old = *ptentry;
    *ptentry = riscv_pt_page_mapping(phys) | page_prots;
    if (pte_empty(old))
    {
        increment_vm_stat(as, resident_set_size, PAGE_SIZE);
    }
    else
    {
        __native_tlb_invalidate_page((void *) PML_EXTRACT_ADDRESS(*ptentry));
    }

    if (!vma_is_pfnmap(vma))
    {
        if (!pte_empty(old) && !pte_special(old))
        {
            /* If old was a thing, decrement the mapcount */
            struct page *oldp = phys_to_page(PML_EXTRACT_ADDRESS(old));
            page_sub_mapcount(oldp);
        }

        struct page *newp = phys_to_page(phys);
        if (!special_mapping)
            page_add_mapcount(newp);
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

bool riscv_get_pt_entry_with_ptables(void *addr, uint64_t **entry_ptr, struct mm_address_space *mm,
                                     struct pt_location location[4])
{
    unsigned long virt = (unsigned long) addr;
    unsigned int indices[riscv_max_paging_levels];

    for (unsigned int i = 0; i < riscv_paging_levels; i++)
    {
        indices[i] = (virt >> 12) >> (i * 9) & 0x1ff;
        location[4 - 1 - i].index = indices[i];
    }

    PML *pml = (PML *) ((unsigned long) mm->arch_mmu.top_pt + PHYS_BASE);
    unsigned int location_index = 0;

    for (unsigned int i = riscv_paging_levels; i != 1; i--)
    {
        uint64_t entry = pml->entries[indices[i - 1]];
        location[location_index].table = pml;
        location[location_index++].index = indices[i - 1];

        if (entry & RISCV_MMU_VALID)
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

bool riscv_get_pt_entry(void *addr, uint64_t **entry_ptr, bool may_create_path,
                        struct mm_address_space *mm)
{
    unsigned long virt = (unsigned long) addr;
    unsigned int indices[riscv_max_paging_levels];

    addr_to_indices(virt, indices);

    PML *pml = (PML *) ((unsigned long) mm->arch_mmu.top_pt + PHYS_BASE);

    for (unsigned int i = riscv_paging_levels; i != 1; i--)
    {
        uint64_t entry = pml->entries[indices[i - 1]];
        if (entry & RISCV_MMU_VALID)
        {
            void *page = (void *) PML_EXTRACT_ADDRESS(entry);
            pml = (PML *) PHYS_TO_VIRT(page);
        }
        else
        {
            if (!may_create_path)
                return false;

            PML *pt = alloc_pt();

            if (!pt)
                return false;
            increment_vm_stat(mm, page_tables_size, PAGE_SIZE);

            pml->entries[indices[i - 1]] = riscv_make_pt_entry_page_table(pt);
            __asm__ __volatile__("sfence.vma zero, zero");

            pml = (PML *) PHYS_TO_VIRT(pt);
        }
    }

    *entry_ptr = &pml->entries[indices[0]];

    return true;
}

bool __paging_change_perms(struct mm_address_space *mm, void *addr, int prot)
{
    MUST_HOLD_MUTEX(&mm->vm_lock);

    uint64_t *entry;
    if (!riscv_get_pt_entry(addr, &entry, false, mm))
    {
        return false;
    }

    uint64_t pt_entry = *entry;
    uint64_t perms = pt_entry & RISCV_MMU_FLAGS_TO_SAVE_ON_MPROTECT;
    uint64_t page = PML_EXTRACT_ADDRESS(pt_entry);

    if (prot & VM_EXEC)
        perms |= RISCV_MMU_EXECUTE;
    if (prot & VM_WRITE)
        perms |= RISCV_MMU_WRITE;
    if (prot & VM_READ)
        perms |= RISCV_MMU_VALID | RISCV_MMU_READ;
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
    uint64_t *ptentry;
    if (!riscv_get_pt_entry(addr, &ptentry, false, mm))
        return false;

    *ptentry = *ptentry & ~RISCV_MMU_WRITE;

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

/**
 * @brief Directly maps a page into the paging tables.
 *
 * @param as The target address space.
 * @param virt The virtual address.
 * @param phys The physical address of the page.
 * @param prot Desired protection flags.
 * @param vma VMA for this mapping (optional)
 * @return NULL if out of memory, else virt.
 */
void *vm_map_page(struct mm_address_space *as, uint64_t virt, uint64_t phys, uint64_t prot,
                  struct vm_area_struct *vma)
{
    return paging_map_phys_to_virt(as, virt, phys, prot, vma);
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
    // TODO: Recognize hugepages here
    if (!riscv_get_pt_entry(addr, &ppt_entry, false, as))
        return PAGE_NOT_PRESENT;

    unsigned long pt_entry = *ppt_entry;

    unsigned long ret = 0;

    if (pt_entry & RISCV_MMU_VALID)
        ret |= PAGE_PRESENT;
    else
    {
        return PAGE_NOT_PRESENT;
    }

    if (pt_entry & RISCV_MMU_USER)
        ret |= PAGE_USER;
    if (pt_entry & RISCV_MMU_WRITE)
        ret |= PAGE_WRITABLE;
    if (pt_entry & RISCV_MMU_EXECUTE)
        ret |= PAGE_EXECUTABLE;
    if (pt_entry & RISCV_MMU_DIRTY)
        ret |= PAGE_DIRTY;
    if (pt_entry & RISCV_MMU_ACCESSED)
        ret |= PAGE_ACCESSED;
    if (pt_entry & RISCV_MMU_GLOBAL)
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
    mm->arch_mmu.top_pt = get_current_page_tables();
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
    if (!riscv_get_pt_entry(addr, &ptentry, false, as))
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
    bool is_wp_page = !(*ptentry & RISCV_MMU_WRITE) && old_prots & VM_WRITE;

    if (is_wp_page)
    {
        new_prots &= ~VM_WRITE;
        // printk("NOT VM_WRITING\n");
    }

    // printk("new prots: %x\n", new_prots);

    unsigned long paddr = PML_EXTRACT_ADDRESS(*ptentry);

    uint64_t page_prots = vm_prots_to_mmu(new_prots);
    *ptentry = riscv_pt_page_mapping(paddr) | page_prots;
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

#define MMU_UNMAP_CAN_FREE_PML 1
#define MMU_UNMAP_OK           0

static int riscv_mmu_unmap(PML *table, unsigned int pt_level, page_table_iterator &it,
                           struct vm_area_struct *vma)
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

#ifdef CONFIG_RISCV_MMU_UNMAP_DEBUG
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

            if (val & RISCV_MMU_ACCESSED)
                invd_tracker.add_page(it.curr_addr(), entry_size);

            if (!vma_is_pfnmap(vma) && !pte_special(val))
            {
                struct page *oldp = phys_to_page(PML_EXTRACT_ADDRESS(val));
                page_sub_mapcount(oldp);
            }

            it.adjust_length(entry_size);
            decrement_vm_stat(it.as_, resident_set_size, entry_size);
        }
        else
        {
            assert((pt_entry & RISCV_MMU_VALID) != 0);
            PML *next_table = (PML *) PHYS_TO_VIRT(PML_EXTRACT_ADDRESS(pt_entry));
            int st = riscv_mmu_unmap(next_table, pt_level - 1, it, vma);

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
    if (pt_level != riscv_paging_levels - 1 && (unmapped_whole_table || pml_is_empty(table)))
    {
        return MMU_UNMAP_CAN_FREE_PML;
    }

#if 0
    printk("nr entries %lu\n", nr_entries);

    printk("unmapping %lu\n", it.length());
#endif

    return MMU_UNMAP_OK;
}

int vm_mmu_unmap(struct mm_address_space *as, void *addr, size_t pages, struct vm_area_struct *vma)
{
    unsigned long virt = (unsigned long) addr;
    size_t size = pages << PAGE_SHIFT;

    page_table_iterator it{virt, size, as};

    PML *first_level = (PML *) PHYS_TO_VIRT(as->arch_mmu.top_pt);

    riscv_mmu_unmap(first_level, riscv_paging_levels - 1, it, vma);

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

    for (const auto pte : pt->entries)
    {
        if (pte_empty(pte))
            continue;

        if (!(pte & RISCV_MMU_USER))
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

static int riscv_mmu_fork(PML *parent_table, PML *child_table, unsigned int pt_level,
                          page_table_iterator &it, struct vm_area_struct *old_region)
{
    unsigned int index = addr_get_index(it.curr_addr(), pt_level);

    /* Get the size that each entry represents here */
    auto entry_size = level_to_entry_size(pt_level);

    unsigned int i;

#ifdef CONFIG_PT_ITERATOR_HAVE_DEBUG
    if (it.debug)
    {
        printk("level %u - index %x\n", pt_level, index);
    }
#endif
    tlb_invalidation_tracker invd_tracker;

    for (i = index; i < PAGE_TABLE_ENTRIES && it.length(); i++)
    {
        const u64 pt_entry = parent_table->entries[i];
        bool pte_empty = pt_entry == 0;

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

        bool is_huge_page = is_huge_page_level(pt_level) && pt_entry_is_huge(pt_entry);

        if (pt_level == PT_LEVEL || is_huge_page)
        {
            const bool should_cow = old_region->vm_maptype == MAP_PRIVATE;
            child_table->entries[i] = pt_entry & (should_cow ? ~RISCV_MMU_WRITE : ~0UL);
            if (!vma_is_pfnmap(old_region) && !pte_special(pt_entry))
                page_add_mapcount(phys_to_page(PML_EXTRACT_ADDRESS(pt_entry)));
            if (should_cow)
            {
                /* Write-protect the parent's page too. Make sure to invalidate the TLB if we
                 * downgraded permissions.
                 */
                __atomic_store_n(&parent_table->entries[i], pt_entry & ~RISCV_MMU_WRITE,
                                 __ATOMIC_RELAXED);

                if (pt_entry & RISCV_MMU_WRITE)
                    invd_tracker.add_page(it.curr_addr(), entry_size);
            }

            increment_vm_stat(it.as_, resident_set_size, entry_size);
            it.adjust_length(entry_size);
        }
        else
        {
            assert((pt_entry & RISCV_MMU_VALID) != 0);

            PML *old = (PML *) PHYS_TO_VIRT(PML_EXTRACT_ADDRESS(pt_entry));
            PML *child_pt = (PML *) PHYS_TO_VIRT(PML_EXTRACT_ADDRESS(child_table->entries[i]));

            if (child_table->entries[i] != 0)
            {
                /* Allocate a new page table for the child process */
                PML *copy = (PML *) alloc_pt();
                if (!copy)
                    return -ENOMEM;

                increment_vm_stat(it.as_, page_tables_size, PAGE_SIZE);

                const unsigned long old_prots = pt_entry & RISCV_PAGING_PROT_BITS;
                /* Set the PTE */
                child_table->entries[i] = (unsigned long) copy | old_prots;
                child_pt = (PML *) PHYS_TO_VIRT(copy);
            }

            int st = riscv_mmu_fork(old, child_pt, pt_level - 1, it, old_region);

            if (st < 0)
            {
                return st;
            }
        }
    }

    return 0;
}

/**
 * @brief Fork MMU page tables
 *
 * @param old_region Old vm_area_struct
 * @param addr_space Current address space
 * @return 0 on success, negative error codes
 */
int mmu_fork_tables(struct vm_area_struct *old_region, struct mm_address_space *addr_space)
{
    page_table_iterator it{old_region->vm_start, vma_pages(old_region) << PAGE_SHIFT, addr_space};

    return riscv_mmu_fork((PML *) PHYS_TO_VIRT(old_region->vm_mm->arch_mmu.top_pt),
                          (PML *) PHYS_TO_VIRT(addr_space->arch_mmu.top_pt),
                          riscv_paging_levels - 1, it, old_region);
}

unsigned int mmu_get_clear_referenced(struct mm_address_space *mm, void *addr, struct page *page)
{
    scoped_lock g{mm->page_table_lock};

    u64 *ptep;
    if (!riscv_get_pt_entry(addr, &ptep, false, mm))
        return 0;

    u64 pte = READ_ONCE(*ptep);
    u64 new_pte;
    do
    {
        if (!(pte & RISCV_MMU_ACCESSED))
            return 0;
        if (PML_EXTRACT_ADDRESS(pte) != (unsigned long) page_to_phys(page))
            return 0;
        new_pte = pte & ~RISCV_MMU_ACCESSED;
    } while (!__atomic_compare_exchange_n(ptep, &pte, new_pte, false, __ATOMIC_RELAXED,
                                          __ATOMIC_RELAXED));
    /* Architectural note: We don't need to flush the TLB. Flushing the TLB is required by riscv if
     * we want the A bit to be set again, but we can just wait for an unrelated TLB flush (e.g
     * context switch) to do the job for us. A TLB shootdown is too much overhead for this purpose.
     */
    return 1;
}
