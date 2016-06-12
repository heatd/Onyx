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
size_t num_areas = 2;
#ifdef __x86_64__
const uintptr_t high_half = 0xFFFF800000000000;
const uintptr_t low_half_max = 0x00007fffffffffff;
const uintptr_t low_half_min = 0x800000;
#endif
void vmm_start_address_bookeeping(uintptr_t framebuffer_address)
{
	areas = malloc(num_areas * sizeof(vmm_entry_t));
	if(!areas)
		panic("Not enough memory\n");
	areas[0].base = KERNEL_VIRTUAL_BASE;
	areas[0].pages = 524288; /* last 2 GB*/
	areas[0].rwx = VMM_RWX; /* RWX */
	areas[0].type = VMM_TYPE_REGULAR;

	areas[1].base = framebuffer_address;
	areas[1].pages = 1024;
	areas[1].rwx = VMM_RW; /* RW- */
	areas[1].type = VMM_TYPE_HW;
}

void *vmm_map_range(void *range, size_t pages, uint64_t flags)
{
	uintptr_t mem = (uintptr_t) range;
	for (size_t pgs = 0; pgs < pages; pgs++) {
		paging_map_phys_to_virt(mem, (uintptr_t)
				      pmalloc(1), flags);
		mem += 0x1000;
	}
	return range;
}
static int vmm_comp(void *ptr1, void *ptr2)
{
	const vmm_entry_t *a = (const vmm_entry_t*) ptr1;
	const vmm_entry_t *b = (const vmm_entry_t*) ptr2;

	return a->base < b->base ? -1 :
		b->base < a->base ?  1 :
		a->pages < b->pages ? -1 :
		b->pages < a->pages ?  1 :
	                            0 ;
}
void *vmm_allocate_virt_address(uint64_t flags, size_t pages, uint32_t type)
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
	areas[num_areas-1].base = best_address;
	areas[num_areas-1].pages = pages;
	areas[num_areas-1].type = type;
	areas[num_areas-1].rwx = VMM_RWX;
	qsort(areas,num_areas,sizeof(vmm_entry_t),vmm_comp);
	return (void*)best_address;
}
void *vmm_reserve_address(void *addr, size_t pages, uint32_t type)
{
	num_areas++;
	areas = realloc(areas, num_areas * sizeof(vmm_entry_t));
	areas[num_areas-1].base = (uintptr_t)addr;
	areas[num_areas-1].pages = pages;
	areas[num_areas-1].type = type;
	areas[num_areas-1].rwx = VMM_RWX;
	qsort(areas,num_areas,sizeof(vmm_entry_t),vmm_comp);
	return addr;
}
