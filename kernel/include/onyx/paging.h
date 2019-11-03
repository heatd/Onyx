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

#define PHYS_BASE (0xffffd00000000000)
#define PAGE_WRITABLE 0x1
#define PAGE_GLOBAL 0x2
#define PAGE_KERNEL (PAGE_GLOBAL|PAGE_WRITABLE)
#define PAGE_TABLE_ENTRIES 512
#undef PAGE_SIZE
#define PAGE_SIZE 4096UL


typedef struct
{
	uint64_t entries[512];
} PML;


#ifdef __cplusplus
extern "C" {
#endif

struct mm_address_space;
struct process;

void paging_init();
void *paging_unmap(void* memory);
void *paging_map_phys_to_virt_large(uintptr_t virt, uintptr_t phys, uint64_t prot);
void *paging_map_phys_to_virt_large_early(uintptr_t virt, uintptr_t phys, uint64_t prot);
void paging_map_all_phys(void);
void *virtual2phys(void *ptr);
int paging_clone_as(struct mm_address_space *addr_space);
int paging_fork_tables(struct mm_address_space *addr_space);
void paging_stop_spawning();
void paging_load_cr3(PML *pml);
void paging_change_perms(void *addr, int perms);
int is_invalid_arch_range(void *address, size_t pages);
void paging_protect_kernel(void);
void paging_invalidate(void *page, size_t pages);
void paging_free_page_tables(struct mm_address_space *mm);

#ifdef __x86_64__
void *x86_placement_map(unsigned long _phys);
#endif

PML *get_current_pml4(void);

#ifdef __cplusplus
}
#endif
#endif
