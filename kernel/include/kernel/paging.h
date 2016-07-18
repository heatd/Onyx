/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _PAGING_H
#define _PAGING_H

#include <stdint.h>
#include <string.h>
#include <kernel/pmm.h>
#define PHYS_BASE (0xFFFFA00000000000)
#define PAGE_WRITABLE 0x1
#define PAGE_GLOBAL 0x2
#define PAGE_KERNEL (PAGE_GLOBAL|PAGE_WRITABLE)
#define PAGES_PER_TABLE 512
typedef struct {uint64_t entries[512];} PML4;
typedef struct {uint64_t entries[512];} PML3;
typedef struct {uint64_t entries[512];} PML2;
typedef struct {uint64_t entries[512];} PML1;
void paging_init();
void* paging_map_phys_to_virt(uintptr_t virt, uintptr_t phys, uint64_t prot);
void paging_map_all_phys(size_t);
void *virtual2phys(void *ptr);
#endif
