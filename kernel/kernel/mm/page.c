/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <cpuid.h>

#include <kernel/page.h>
#include <kernel/vmm.h>
#include <kernel/bootmem.h>
#include <kernel/log.h>
#include <kernel/paging.h>
#include <kernel/panic.h>

static page_zone_t zones[3] = {0};
//static size_t memory_size = 0;

static _Bool is_initialized = false;
#define ACCESS_ZONE(x) ((page_area_t*) PHYS_TO_VIRT(x))
void page_initalize_memory()
{
	/* Set the zones' names */
	zones[0].name = "DMA";
	zones[1].name = "highmem/DMA32";
	zones[2].name = "highmem64";

	page_area_t *zone0 = NULL, *zone1 = NULL, *zone2 = NULL;
	/* Start initializing the zones */
	for(void *ptr = bootmem_alloc(1); ptr; ptr = bootmem_alloc(1))
	{
		if(IS_DMA_PTR(ptr))
		{
			if(!zone0)
			{
				zone0 = ptr;
				zones[0].free_areas = zone0;
			}
			else
			/* Link the blocks */
			{
				ACCESS_ZONE(zone0)->next = ptr;
				ACCESS_ZONE(ACCESS_ZONE(zone0)->next)->prev = zone0;
				zone0 = ACCESS_ZONE(zone0)->next;
			}
			/* Increment the free pages and the size of the zone */
			zones[0].size += PAGE_SIZE;
			zones[0].free_pages++;
		}
		else if(IS_HIGHMEM_PTR(ptr))
		{
			if(!zone1)
			{
				zone1 = ptr;
				zones[1].free_areas = zone1;
			}
			else
			/* Link the blocks */
			{
				ACCESS_ZONE(zone1)->next = ptr;
				ACCESS_ZONE(ACCESS_ZONE(zone1)->next)->prev = zone1;
				zone1 = ACCESS_ZONE(zone1)->next;
			}
			/* Increment the free pages and the size of the zone */
			zones[1].size += PAGE_SIZE;
			zones[1].free_pages++;
		}
		else if(IS_HIGHMEM64_PTR(ptr))
		{
			if(!zone2)
			{
				zone2 = ptr;
				zones[2].free_areas = zone2;
			}
			else
			/* Link the blocks */
			{
				ACCESS_ZONE(zone2)->next = ptr;
				ACCESS_ZONE(ACCESS_ZONE(zone2)->next)->prev = zone2;
				zone2 = ACCESS_ZONE(zone2)->next;
			}
			/* Increment the free pages and the size of the zone */
			zones[2].size += PAGE_SIZE;
			zones[2].free_pages++;
		}
		else
		{
			/* Print an error message and halt */
			FATAL("page", "BUG: page_initialize_memory() failed to recognize the corresponding memory area\n");
			SUBMIT_BUG_REPORT("page allocator");
			halt();
		}
	}
}
/* Initialize the page allocator */
void page_init(void)
{
	/* Get the amount of memory present in the system */
	//memory_size = bootmem_get_memory_size();

	/* Setup the memory linked lists */
	page_initalize_memory();

	is_initialized = true;
}
void *__alloc_page(int opt)
{
	if(!is_initialized)
		return bootmem_alloc(1);
	/* Figure out which zone the caller wants */
	int zone = -1;
	if(opt & PAGE_AREA_DMA)
		zone = 0;
	else if(opt & PAGE_AREA_HIGH_MEM)
		zone = 1;
	else if(opt & PAGE_AREA_HIGH_MEM_64)
		zone = 2;

	/* If the zone is invalid, just fail */
	if(zone < 0)
		return NULL;
	page_zone_t *z = &zones[zone];

	/* Lock the zone */
	acquire_spinlock(&z->lock);
	/* If there aren't enough pages in this zone, and the caller doesn't want us to retry, just fail */
	if(z->free_pages == 0 && (opt & PAGE_NO_RETRY))
	{
		release_spinlock(&z->lock);
		return NULL;
	}
	void *return_address = z->free_areas;
	z->free_areas = ((page_area_t*) PHYS_TO_VIRT(z->free_areas))->next;
	release_spinlock(&z->lock);
	memset(PHYS_TO_VIRT(return_address), 0, PAGE_SIZE);
	return return_address;
}
void __free_page(void *page)
{
	int zone = 0;
	if(IS_DMA_PTR(page))
	{
		zone = 0;
	}
	else if(IS_HIGHMEM_PTR(page))
	{
		zone = 1;
	}
	else if(IS_HIGHMEM64_PTR(page))
	{
		zone = 2;
	}
	page_zone_t *z = &zones[zone];

	acquire_spinlock(&z->lock);
	z->free_pages++;
	z->allocated_pages--;
	page_area_t *pages = z->free_areas;

	if(!pages)
	{
		z->free_areas = page;
		memset(z->free_areas, 0, PAGE_SIZE);
	}
	else
	{
		page_area_t *new_page = ACCESS_ZONE(page);
		new_page->next = z->free_areas;
		ACCESS_ZONE(z->free_areas)->prev = page;
		z->free_areas = page;
	}
	release_spinlock(&z->lock);
}
