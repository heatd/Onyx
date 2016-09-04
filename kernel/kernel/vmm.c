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
#include <kernel/paging.h>
#include <kernel/vmm.h>
#include <stdio.h>
#include <stdbool.h>
#include <kernel/panic.h>
_Bool isInitialized = false;
_Bool is_spawning = 0;
vmm_entry_t *old_entries = NULL;
size_t old_num_entries = 0;
void vmm_init()
{
	isInitialized = true;
	paging_init();
}
uintptr_t max(uintptr_t x, uintptr_t y)
{
	return x > y ? x : y;
}
uintptr_t min(uintptr_t x, uintptr_t y)
{
	return x < y ? x : y;
}
vmm_entry_t *areas = NULL;
size_t num_areas = 3;
#ifdef __x86_64__
const uintptr_t high_half = 0xFFFF800000000000;
const uintptr_t low_half_max = 0x00007fffffffffff;
const uintptr_t low_half_min = 0x400000;
#endif
void vmm_start_address_bookeeping(uintptr_t framebuffer_address, uintptr_t heap)
{
	areas = malloc(num_areas * sizeof(vmm_entry_t));
	if(!areas)
		panic("Not enough memory\n");
	areas[0].base = KERNEL_VIRTUAL_BASE;
	areas[0].pages = 524288; /* last 2 GB*/
	areas[0].rwx = VMM_WRITE | VMM_GLOBAL; /* RWX */
	areas[0].type = VMM_TYPE_REGULAR;

	areas[1].base = framebuffer_address;
	areas[1].pages = 1024;
	areas[1].rwx = VMM_WRITE | VMM_NOEXEC; /* RW- */
	areas[1].type = VMM_TYPE_HW;

	areas[2].base = heap;
	areas[2].pages = 1024;
	areas[2].rwx = VMM_WRITE | VMM_GLOBAL | VMM_NOEXEC; /* RW- */
	areas[2].type = VMM_TYPE_REGULAR;
}

void *vmm_map_range(void *range, size_t pages, uint64_t flags)
{
	uintptr_t mem = (uintptr_t) range;
	for (size_t pgs = 0; pgs < pages; pgs++) {
		paging_map_phys_to_virt(mem, (uintptr_t)
				      pmalloc(1), flags);
		mem += 0x1000;
	}
	memset(range, 0, 4096 * pages);
	return range;
}
static int vmm_comp(const void *ptr1, const void *ptr2)
{
	const vmm_entry_t *a = (const vmm_entry_t*) ptr1;
	const vmm_entry_t *b = (const vmm_entry_t*) ptr2;

	return a->base < b->base ? -1 :
		b->base < a->base ?  1 :
		a->pages < b->pages ? -1 :
		b->pages < a->pages ?  1 :
	                            0 ;
}
void *vmm_allocate_virt_address(uint64_t flags, size_t pages, uint32_t type, uint64_t prot)
{
	uintptr_t base_address = 0;
	switch(type)
	{
		case VMM_TYPE_SHARED:
		case VMM_TYPE_STACK:
		{
			if(!(flags & 1))
				base_address = 0x00007a0000000000;
			else
				base_address = 0xfffff7a000000000;
			break;
		}
		default:
		case VMM_TYPE_REGULAR:
		{
			if(flags & 1)
				base_address = high_half;
			else
				base_address = low_half_min;
			break;
		}
	}
	uintptr_t best_address = base_address;
	for(size_t i = 0; i < num_areas; i++)
	{
		if(areas[i].base == best_address)
			best_address = areas[i].base + areas[i].pages * PAGE_SIZE;
		if(areas[i].base < best_address && areas[i].base + areas[i].pages * PAGE_SIZE > best_address)
			best_address = areas[i].base + areas[i].pages * PAGE_SIZE;
	}
	num_areas++;
	areas = realloc(areas, num_areas * sizeof(vmm_entry_t));
	if(!areas)
		panic("Severe OOM!");
	areas[num_areas-1].base = best_address;
	areas[num_areas-1].pages = pages;
	areas[num_areas-1].type = type;
	areas[num_areas-1].rwx = prot;
	qsort(areas,num_areas,sizeof(vmm_entry_t),vmm_comp);
	return (void*)best_address;
}
void *vmm_reserve_address(void *addr, size_t pages, uint32_t type, uint64_t prot)
{	num_areas++;
	areas = realloc(areas, num_areas * sizeof(vmm_entry_t));
	if(!areas)
		panic("Severe OOM!");

	areas[num_areas-1].base = (uintptr_t)addr;
	areas[num_areas-1].pages = pages;
	areas[num_areas-1].type = type;
	areas[num_areas-1].rwx = prot;
	qsort(areas,num_areas,sizeof(vmm_entry_t),vmm_comp);
	return addr;
}
vmm_entry_t *vmm_is_mapped(void *addr)
{
	for(size_t i = 0; i < num_areas; i++)
	{
		if(areas[i].base == (uintptr_t)addr)
			return &areas[i];
		if(areas[i].base + areas[i].pages * 4096 > (uintptr_t) addr && areas[i].base < (uintptr_t) addr)
			return &areas[i];
	}
	return NULL;
}
PML4 *vmm_clone_as(vmm_entry_t **vmmstructs)
{
	PML4 *pt = paging_clone_as();
	printf("Cloned the paging structures\n");
	vmm_entry_t *entries;
	size_t remaining_entries = 0;
	for(size_t i = 0; i < num_areas; i++)
	{
		if(areas[i].base <= high_half)
			remaining_entries++;
	}
	entries = malloc(sizeof(vmm_entry_t) * remaining_entries);
	size_t curr_entry = 0;
	for(size_t i = 0; i < num_areas; i++)
	{
		if(areas[i].base <= high_half)
		{
			memcpy(&entries[i], &areas[i], sizeof(vmm_entry_t));
		}
	}
	is_spawning = 1;
	old_entries = areas;
	old_num_entries = num_areas;
	*vmmstructs = entries;
	areas = entries;
	num_areas = remaining_entries;
	qsort(areas,num_areas,sizeof(vmm_entry_t),vmm_comp);
	return pt;
}
PML4 *vmm_fork_as(vmm_entry_t **vmmstructs)
{
	PML4 *pt = paging_fork_as();
	vmm_entry_t *entries = malloc(sizeof(vmm_entry_t) * num_areas);
	memcpy(entries, areas, sizeof(vmm_entry_t) * num_areas);
	is_spawning = 1;
	old_entries = areas;
	old_num_entries = num_areas;
	*vmmstructs = entries;
	areas = entries;
	return pt;
}
void vmm_stop_spawning()
{
	is_spawning = 0;
	areas = old_entries;
	num_areas = old_num_entries;
	paging_stop_spawning();
}