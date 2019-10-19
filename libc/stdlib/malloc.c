/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>

#ifdef __is_onyx_kernel
#include <onyx/vm.h>
#include <onyx/spinlock.h>
#include <onyx/mm/kasan.h>
#include <onyx/heap.h>

extern bool is_initialized;

static struct heap heap = {};

uintptr_t starting_address = 0;

struct heap *heap_get()
{
	return &heap;
}

size_t heap_get_used_pages(void)
{
	return heap.size / PAGE_SIZE;
}

void heap_set_start(uintptr_t heap_start)
{
	starting_address = heap_start;
	heap.starting_address = (void *) heap_start;
	heap.brk = heap.starting_address;
	heap.size = 0;
}

#include <stdio.h>

static struct spinlock heap_lock;
void *expand_heap(size_t size)
{
	size_t nr_pages = (size >> PAGE_SHIFT) + 3;

	void *alloc_start = (void *) ((char *) heap.starting_address + heap.size);

	//printk("Expanding heap from %p to %lx\n", alloc_start, (unsigned long) alloc_start + (nr_pages << PAGE_SHIFT));
	if(!vm_map_range(alloc_start, nr_pages, VM_WRITE | VM_NOEXEC | VM_DONT_MAP_OVER))
		return NULL;

	heap.size += nr_pages << PAGE_SHIFT;
#ifdef CONFIG_KASAN
	kasan_alloc_shadow((unsigned long) alloc_start, nr_pages << PAGE_SHIFT, -1);
#endif
	return alloc_start;
}

void *do_brk_change(intptr_t inc)
{
	assert(heap.brk != NULL);
	void *old_brk = heap.brk;
	
	uintptr_t new_brk = (uintptr_t) heap.brk + inc;
	uintptr_t starting_address = (uintptr_t) heap.starting_address;
	unsigned long heap_limit = starting_address + heap.size;
	if(new_brk >= heap_limit)
	{
		size_t size = new_brk - heap_limit;

		void *ptr = expand_heap(size);
		if(!ptr)
			return errno = ENOMEM, (void *) -1;
	}

	heap.brk = (void*) new_brk;

	return old_brk;
}

void *sbrk(intptr_t inc)
{
	return do_brk_change(inc);
}

void *zalloc(size_t size)
{
	return calloc(1, size);
}
#endif
