/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _PAGING_H
#define _PAGING_H

#include <stdint.h>
#include <string.h>
#include <onyx/bootmem.h>

#define PHYS_BASE               (0xffffd00000000000)
#define PHYS_BASE_LIMIT         (0xffffd08000000000)

#define PAGE_NOT_PRESENT	0


#define PAGE_TABLE_ENTRIES 512

#ifdef __x86_64__

#undef PAGE_SIZE
#define PAGE_SIZE 4096UL


typedef struct
{
	uint64_t entries[512];
} PML;

#endif


#ifdef __cplusplus
extern "C" {
#endif

struct mm_address_space;
struct process;

void paging_init(void);
void *paging_map_phys_to_virt_large_early(uintptr_t virt, uintptr_t phys, uint64_t prot);
void paging_map_all_phys(void);
void *virtual2phys(void *ptr);
int paging_clone_as(struct mm_address_space *addr_space);
int paging_fork_tables(struct mm_address_space *addr_space);
void paging_load_cr3(PML *pml);
bool paging_change_perms(void *addr, int prot);
bool __paging_change_perms(struct mm_address_space *mm, void *addr, int prot);
int is_invalid_arch_range(void *address, size_t pages);
void paging_protect_kernel(void);
void paging_free_page_tables(struct mm_address_space *mm);
bool paging_write_protect(void *addr, struct mm_address_space *mm);
int vm_mmu_unmap(struct mm_address_space *as, void *addr, size_t pages);
void *paging_unmap(void* memory);

#ifdef __x86_64__

void *x86_placement_map(unsigned long _phys);

#endif

PML *get_current_pml4(void);

#define PAGE_PRESENT 		(1 << 0)
#define PAGE_GLOBAL 		(1 << 1)
#define PAGE_WRITABLE 		(1 << 2)
#define PAGE_EXECUTABLE 	(1 << 3)
#define PAGE_DIRTY		    (1 << 4)
#define PAGE_ACCESSED		(1 << 5)
#define PAGE_USER		    (1 << 6)

#define MAPPING_INFO_PADDR(x)	(x & -PAGE_SIZE)

/* get_mapping_info: Returns paddr | flags */
unsigned long get_mapping_info(void *addr);
unsigned long __get_mapping_info(void *addr, struct mm_address_space *as);

#ifdef __cplusplus
}
#endif
#endif
