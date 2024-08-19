/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _PAGING_H
#define _PAGING_H

#include <stdint.h>
#include <string.h>

#include <onyx/bootmem.h>
#include <onyx/compiler.h>

#include <platform/page.h>

__BEGIN_CDECLS

#define PHYS_BASE       (0xffffd00000000000)
#define PHYS_BASE_LIMIT (0xffffd08000000000)

#define PAGE_NOT_PRESENT 0

#define PAGE_TABLE_ENTRIES 512

#ifdef __x86_64__

#undef PAGE_SIZE
#define PAGE_SIZE 4096UL

typedef struct
{
    uint64_t entries[512];
} PML;

#undef PHYS_BASE
#undef PHYS_BASE_LIMIT

extern unsigned long __x86_phys_base;
extern unsigned long __x86_phys_base_limit;
#define PHYS_BASE       __x86_phys_base
#define PHYS_BASE_LIMIT __x86_phys_base_limit

#elif __riscv

#undef PAGE_SIZE
#define PAGE_SIZE 4096UL

typedef struct
{
    uint64_t entries[512];
} PML;

#elif __aarch64__

#undef PAGE_SIZE
#define PAGE_SIZE 4096UL

typedef struct
{
    uint64_t entries[512];
} PML;

#endif

struct mm_address_space;
struct process;
struct vm_area_struct;

void paging_init(void);
void paging_map_all_phys(void);
void *virtual2phys(void *ptr);

/**
 * @brief Clone the architecture specific part of an address space
 *
 * @param addr_space The new address space
 * @param original The original address space
 * @return 0 on success, negative error codes
 */
int paging_clone_as(struct mm_address_space *addr_space, struct mm_address_space *original);

int paging_fork_tables(struct mm_address_space *addr_space);
bool paging_change_perms(void *addr, int prot);
bool __paging_change_perms(struct mm_address_space *mm, void *addr, int prot);
int is_invalid_arch_range(void *address, size_t pages);
void paging_protect_kernel(void);
void paging_free_page_tables(struct mm_address_space *mm);
bool paging_write_protect(void *addr, struct mm_address_space *mm);
int vm_mmu_unmap(struct mm_address_space *as, void *addr, size_t pages, struct vm_area_struct *vma);

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
                  struct vm_area_struct *vma);

#ifdef __x86_64__

void *x86_placement_map(unsigned long _phys);

#endif

/**
 * @brief Fork MMU page tables
 *
 * @param old_region Old vm_area_struct
 * @param addr_space Current address space
 * @return 0 on success, negative error codes
 */
int mmu_fork_tables(struct vm_area_struct *old_region, struct mm_address_space *addr_space);

#define PAGE_PRESENT    (1 << 0)
#define PAGE_GLOBAL     (1 << 1)
#define PAGE_WRITABLE   (1 << 2)
#define PAGE_EXECUTABLE (1 << 3)
#define PAGE_DIRTY      (1 << 4)
#define PAGE_ACCESSED   (1 << 5)
#define PAGE_USER       (1 << 6)
#define PAGE_HUGE       (1 << 7)

#define MAPPING_INFO_PADDR(x) (x & -PAGE_SIZE)

/* get_mapping_info: Returns paddr | flags */
unsigned long get_mapping_info(void *addr);
unsigned long __get_mapping_info(void *addr, struct mm_address_space *as);

struct vm_pf_context;
struct page;
unsigned int mmu_get_clear_referenced(struct mm_address_space *mm, void *addr, struct page *page);
int try_to_unmap_one(struct page *page, struct vm_area_struct *vma, unsigned long addr);
int do_wp_page(struct vm_pf_context *context);

__END_CDECLS

#endif
