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
#define PAGE_SIZE 4096


typedef struct {uint64_t entries[512];} PML4;
typedef struct {uint64_t entries[512];} PML3;
typedef struct {uint64_t entries[512];} PML2;
typedef struct {uint64_t entries[512];} PML1;
#ifdef __cplusplus
extern "C" {
#endif
void paging_init();
void *paging_unmap(void* memory);
void *paging_map_phys_to_virt(uintptr_t virt, uintptr_t phys, uint64_t prot);
void *paging_map_phys_to_virt_large(uintptr_t virt, uintptr_t phys, uint64_t prot);
void *paging_map_phys_to_virt_large_early(uintptr_t virt, uintptr_t phys, uint64_t prot);
void *paging_map_phys_to_virt_huge(uint64_t virt, uint64_t phys, uint64_t prot);
void paging_map_all_phys(void);
void *virtual2phys(void *ptr);
PML4 *paging_clone_as();
PML4 *paging_fork_as();
void paging_stop_spawning();
void paging_load_cr3(PML4 *pml);
void paging_change_perms(void *addr, int perms);
int is_invalid_arch_range(void *address, size_t pages);
void paging_protect_kernel(void);

PML4 *get_current_pml4(void);
#ifdef __cplusplus
}
#endif
#endif
