/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
/* Zoned buddy physical memory allocator */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <limits.h>

#include <kernel/vmm.h>
#include <kernel/page.h>
#include <kernel/bootmem.h>
#include <kernel/panic.h>

typedef struct stack_entry
{
	uintptr_t base;
	size_t size;
	size_t magic;
} stack_entry_t;
typedef struct stack
{
	stack_entry_t* next;
} stack_t;

inline unsigned long pow2(int exp)
{
	return (1UL << (unsigned long) exp);
}
inline size_t align_pow2_up(size_t i)
{
	return pow2(ilog2(i) + 1);
}
inline size_t align_pow2_down(size_t i)
{
	return pow2(ilog2(i));
}
inline void __bitmap_mark(size_t bitndx, uint8_t *ptr)
{
	size_t byte_ndx = bitndx / CHAR_BIT;
	uint8_t *byte = &ptr[byte_ndx];
	size_t ndx = bitndx - byte_ndx * CHAR_BIT; 
	*byte |= (1 << ndx);
}
inline void __bitmap_unmark(size_t bitndx, uint8_t *ptr)
{
	size_t byte_ndx = bitndx / CHAR_BIT;
	uint8_t *byte = &ptr[byte_ndx];
	size_t ndx = bitndx - byte_ndx * CHAR_BIT;
	*byte &= ~(1 << ndx);
}
inline bool __bitmap_ismarked(size_t bitndx, uint8_t *ptr)
{
	size_t byte_ndx = bitndx / CHAR_BIT;
	uint8_t *byte = &ptr[byte_ndx];
	size_t ndx = bitndx - byte_ndx * CHAR_BIT;
	return (*byte & (1 << ndx));
}
inline size_t get_block_index(void *ptr, size_t order_size)
{
	return (uintptr_t) ptr / order_size;
}
inline bool is_even_number(size_t s)
{
	return (s & 1) == 0;
}
void buddy_mark_as_used(void *ptr, size_t order_size, uint8_t *bitmap)
{
	__bitmap_mark(get_block_index(ptr, order_size), bitmap);
}
void buddy_mark_as_free(void *ptr, size_t order_size, uint8_t *bitmap)
{
	__bitmap_unmark(get_block_index(ptr, order_size), bitmap);
}
bool buddy_is_free(void *ptr, size_t order_size, uint8_t *bitmap)
{
	return !__bitmap_ismarked(get_block_index(ptr, order_size), bitmap);
}
void list_append(struct list_head *list, void *mem)
{
	if(!list->ptr)
	{
		list->ptr = mem;
		list->next = NULL;
		return;
	}
	while(list->next)
		list = list->next;
	list->next = PHYS_TO_VIRT(mem);
	list->next->ptr = mem;
	list->next->next = NULL;
}
free_area_t free_areas[MAX_ORDER] = {0};
static bool buddy_is_initialized = false;
static spinlock_t buddy_lock = {0};
#define ACCESS_ZONE(x) ((page_area_t*) PHYS_TO_VIRT(x))

void page_initalize_memory(void)
{
	/* Start initializing the zones */
	size_t nentries = 0;
	stack_t *stack = bootmem_get_pstack(&nentries);
	size_t size_memory = bootmem_get_memsize();
	for(int i = 0; i < MAX_ORDER; i++)
	{
		size_t bsize = pow2(i) * PAGE_SIZE;
		size_t bitmap_size = size_memory / bsize / CHAR_BIT;
		free_areas[i].map = bootmem_alloc(vmm_align_size_to_pages(bitmap_size));
		if(!free_areas[i].map)
			panic("early oom at page_initialize_memory()");
		free_areas[i].map = PHYS_TO_VIRT(free_areas[i].map);
		/* Set everything as used */
		memset(free_areas[i].map, 0xff, bitmap_size);
	}
	/* Now, parse through the stack */
	for(size_t i = 0; i < nentries; i++)
	{
		if(stack->next[i].base != 0 && stack->next[i].size != 0)
		{
			ssize_t npages = (ssize_t) stack->next[i].size / PAGE_SIZE;
			size_t rounded_down = align_pow2_down(npages);
			while(npages > 0)
			{
				rounded_down = align_pow2_down(npages);

				size_t order = ilog2(rounded_down);
				if(order >= MAX_ORDER)
					order = MAX_ORDER - 1;
				size_t size_order = pow2(order) * PAGE_SIZE;
				list_append(&free_areas[order].free_list, (void*) stack->next[i].base);
				buddy_mark_as_free((void*) stack->next[i].base, size_order, 
					(uint8_t*) free_areas[order].map);
				stack->next[i].base += size_order;
				stack->next[i].size -= size_order;
				npages -= pow2(order);
			}
		}
	}
}
/* Initialize the page allocator */
void page_init(void)
{
	/* Setup the memory linked lists */
	page_initalize_memory();

	buddy_is_initialized = true;
}
void *buddy_get_page(int order)
{
	/* Try to find a page of order 'order' ready for allocation, without splitting bigger blocks */
	free_area_t *area = &free_areas[order];
	if(area->free_list.ptr)
	{
		void *ret = area->free_list.ptr;
		if(area->free_list.next)
		{
			area->free_list.ptr = area->free_list.next->ptr;
			area->free_list.next = area->free_list.next->next;
		}
		else
		{
			area->free_list.ptr = NULL;
		}
		/* Set it as used on the bitmap */
		buddy_mark_as_used(ret, pow2(order) * PAGE_SIZE, (uint8_t*) area->map);
		return ret;
	}
	return NULL;
}
void buddy_split_block(void *area, int target_order)
{
	void *first_half = area;
	void *second_half = (void*)((uintptr_t) area + pow2(target_order) * PAGE_SIZE);
	/* Add both blocks to the order */
	list_append(&free_areas[target_order].free_list, first_half);
	list_append(&free_areas[target_order].free_list, second_half);
	buddy_mark_as_free(first_half, pow2(target_order) * PAGE_SIZE, (uint8_t*) free_areas[target_order].map);
	buddy_mark_as_free(second_half, pow2(target_order) * PAGE_SIZE, (uint8_t*) free_areas[target_order].map);
}
void buddy_add_page(void *area, int order)
{
	list_append(&free_areas[order].free_list, area);
}
void *buddy_alloc_pages(int order)
{
	/* First try to find a suitable area */
	void *area = buddy_get_page(order);
	if(area)
		return area;
	/* If we didn't find a valid order and order is already the biggest one, return NULL */
	if(order + 1 >= MAX_ORDER)
		return NULL;
	/* If not, this is going to be slightly more complicated */
	void *bigger_area = buddy_alloc_pages(order + 1);
	if(!bigger_area)
		return NULL;
	/* Split the block and retry */
	buddy_split_block(bigger_area, order);
	area = buddy_get_page(order);
	return area;
}
void buddy_free_pages(void *pages, int order)
{
	size_t order_size = pow2(order) * PAGE_SIZE; 
	/* Add the page back into the list */
	buddy_add_page(pages, order);

	/* If order is the maximum order, return as we can't merge anything */
	if(order + 1 == MAX_ORDER)
		return;
	uintptr_t buddy = is_even_number(get_block_index(pages, order_size)) ? (uintptr_t) pages + order_size : (uintptr_t) pages - order_size;
	/* Mark pages as free in the bitmap */
	buddy_mark_as_free(pages, order_size, (uint8_t*) free_areas[order].map);
	if(buddy_is_free((void*) buddy, order_size, (uint8_t*) free_areas[order].map))
	{
		buddy_mark_as_used(pages, order_size, (uint8_t*) free_areas[order].map);
		buddy_mark_as_used((void*) buddy, order_size, (uint8_t*) free_areas[order].map);
		/* Merge the two buddies */
		uintptr_t new_block = buddy < (uintptr_t) pages ? buddy : (uintptr_t) pages;
		buddy_add_page((void*) new_block, order + 1);
	}
}
void *__alloc_pages(int order)
{
	if(buddy_is_initialized == false)
		return bootmem_alloc(pow2(order));
	/* assert on order >= MAX_ORDER */
	//assert(order < MAX_ORDER);
	/* Enter the critical section */
	acquire_spinlock(&buddy_lock);
	
	/* Call the allocator's "backend" */
	void *mem = buddy_alloc_pages(order);
	if(mem) memset(PHYS_TO_VIRT(mem), 0, pow2(order) * PAGE_SIZE);
	/* Exit the critical section */
	release_spinlock(&buddy_lock);
	return mem;
}
void *__alloc_page(int opt)
{
	(void) opt;
	return __alloc_pages(0);
}
void __free_pages(void *pages, int order)
{
	// assert(order < MAX_ORDER);
	
	/* Enter the critical section */
	acquire_spinlock(&buddy_lock);
	/* Call the backend */
	buddy_free_pages(pages, order);
	/* Exit the critical section */
	release_spinlock(&buddy_lock);
}
void __free_page(void *page)
{
	__free_pages(page, 0);
}
void page_get_stats(struct memstat *memstat)
{
	// memstat->free_mem = (zones[0].free_pages + zones[1].free_pages + zones[2].free_pages) * PAGE_SIZE;
	// memstat->allocated_mem = (zones[0].allocated_pages + zones[1].allocated_pages + zones[2].allocated_pages) * PAGE_SIZE;
}
