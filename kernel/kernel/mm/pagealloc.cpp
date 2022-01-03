/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <onyx/spinlock.h>
#include <onyx/page.h>
#include <onyx/vm.h>
#include <onyx/panic.h>
#include <onyx/copy.h>
#include <onyx/utils.h>
#include <onyx/atomic.hpp>

size_t page_memory_size;
size_t nr_global_pages;
atomic<size_t> used_pages = 0;

static inline unsigned long pow2(int exp)
{
	return (1UL << (unsigned long) exp);
}

struct page_list 
{
	struct page *page;
	struct list_head list_node;
};

struct page_arena
{
	void *start_arena;
	void *end_arena;
	struct list_head arena_list_node;

	struct page *alloc_contiguous(size_t nr_pgs, unsigned long flags);
};

class page_node
{
private:
	struct spinlock node_lock;
	struct list_head arena_list;
	struct list_head cpu_list_node;
	struct list_head page_list;
	unsigned long used_pages;
	unsigned long total_pages;

	int page_add(struct page_arena *arena, void *__page,
	             struct bootmodule *modules);
public:
	constexpr page_node() : node_lock{}, arena_list{}, cpu_list_node{},
	                        page_list{}, used_pages{}, total_pages{}
	{
	}

	~page_node() {}

	void init()
	{
		INIT_LIST_HEAD(&arena_list);
		INIT_LIST_HEAD(&cpu_list_node);
		INIT_LIST_HEAD(&page_list);
	}

	void add_region(unsigned long base, size_t size, struct bootmodule *module);
	struct page *allocate_pages(unsigned long nr_pages, unsigned long flags);
	struct page *alloc_page(unsigned long flags);
	struct page *alloc_contiguous(unsigned long nr_pages, unsigned long flags);
	void free_page(struct page *p);
};

static bool page_is_initialized = false;
static constexpr size_t arena_default_size = 0x200000;

page_node main_node;


#include <onyx/clock.h>

#define ADDRESS_4GB_MARK		0x100000000

bool page_is_used(void *__page, struct bootmodule *modules);

int page_node::page_add(struct page_arena *arena, void *__page,
	struct bootmodule *modules)
{
	nr_global_pages++;
	total_pages++;

	if(page_is_used(__page, modules))
	{
		struct page *p = page_add_page(__page);
		p->ref = 1;
		return -1;
	}

	struct page_list *page = (struct page_list *) PHYS_TO_VIRT(__page);

	page->page = page_add_page(__page);
	page->page->flags |= PAGE_FLAG_FREE;
	list_add(&page->list_node, &page_list);

	return 0;
}

void page_node::add_region(uintptr_t base, size_t size, struct bootmodule *module)
{
	while(size)
	{
		size_t area_size = min(size, arena_default_size);
		struct page_arena *arena = (struct page_arena *) __ksbrk(sizeof(struct page_arena));
		assert(arena != NULL);
		memset_s(arena, 0, sizeof(struct page_arena));

		arena->start_arena = (void*) base;
		arena->end_arena = (void*) (base + area_size);

		for(size_t i = 0; i < area_size; i += PAGE_SIZE)
		{
			/* If the page is being used, decrement the free_pages counter */
			if(page_add(arena, (void*) (base + i), module) < 0)
			{
				used_pages++;
				::used_pages++;
			}
		}

		list_add_tail(&arena->arena_list_node, &arena_list);

		size -= area_size;
		base += area_size;
	}
}

void page_init(size_t memory_size, unsigned long maxpfn, void *(*get_phys_mem_region)(uintptr_t *base,
	uintptr_t *size, void *context), struct bootmodule *modules)
{	
	uintptr_t region_base;
	uintptr_t region_size;
	void *context_cookie = NULL;
	main_node.init();

	printf("page: Memory size: %lu\n", memory_size);
	page_memory_size = memory_size;
	//nr_global_pages = vm_align_size_to_pages(memory_size);

	size_t nr_arenas = page_memory_size / arena_default_size;
	if(page_memory_size % arena_default_size)
		nr_arenas++;

	size_t needed_memory = nr_arenas *
		sizeof(struct page_arena) + 
		maxpfn * sizeof(struct page);
	void *ptr = alloc_boot_page(vm_size_to_pages(needed_memory), 0);
	if(!ptr)
	{
		halt();
	}

	__kbrk(PHYS_TO_VIRT(ptr), (void *)((unsigned long) PHYS_TO_VIRT(ptr) + needed_memory));
	page_allocate_pagemap(maxpfn);

	/* The context cookie is supposed to be used as a way for the
	 * get_phys_mem_region implementation to keep track of where it's at,
	 * without needing ugly global variables.
	*/

	/* Loop this call until the context cookie is NULL
	* (we must have reached the end)
	*/

	while((context_cookie = get_phys_mem_region(&region_base,
		&region_size, context_cookie)) != NULL)
	{
		/* page_add_region can't return an error value since it halts
		 * on failure
		*/
		main_node.add_region(region_base, region_size, modules);
	}

	page_is_initialized = true;
}

#include <onyx/pagecache.h>
#include <onyx/heap.h>

void page_get_stats(struct memstat *m)
{
	m->total_pages = nr_global_pages;
	m->allocated_pages = used_pages;
	m->page_cache_pages = pagecache_get_used_pages();
	m->kernel_heap_pages = heap_get_used_pages();
}

extern unsigned char kernel_end;

void *kernel_break = &kernel_end;
static void *kernel_break_limit = NULL;

__attribute__((malloc))
void *__ksbrk(long inc)
{
	void *ret = kernel_break;
	kernel_break = (char*) kernel_break + inc;

	assert((unsigned long) kernel_break <= (unsigned long) kernel_break_limit);
	return ret;
}

void __kbrk(void *break_, void *kbrk_limit)
{
	kernel_break = break_;
	kernel_break_limit = kbrk_limit;
}

void free_pages(struct page *pages)
{
	assert(pages != NULL);
	struct page *next = NULL;

	for(struct page *p = pages; p != NULL; p = next)
	{
		next = p->next_un.next_allocation;
		free_page(p);
	}
}



void free_page(struct page *p)
{
	assert(p != NULL);
	assert(p->ref != 0);

	if(__page_unref(p) == 0)
	{
		p->next_un.next_allocation = NULL;
		main_node.free_page(p);
		//printf("free pages %p, %p\n", page_to_phys(p), __builtin_return_address(0));
	}
#if 0
	else
	{
		printf("unref pages %p(refs %lu), %p\n", page_to_phys(p), p->ref, __builtin_return_address(0));
	}
#endif
}

struct page *page_node::alloc_page(unsigned long flags)
{
	struct page *ret = nullptr;
	struct page_list *p = nullptr;

	/* The slow, alloc_contiguous function is the one that handles those requests */
	if(flags & PAGE_ALLOC_4GB_LIMIT)
		return alloc_contiguous(1, flags);

	unsigned long cpu_flags = spin_lock_irqsave(&node_lock);

	if(list_is_empty(&page_list))
	{
		assert(used_pages == total_pages);
		goto out;
	}

	p = container_of(list_first_element(&page_list), struct page_list, list_node);

	list_remove(&p->list_node);
	
	p->page->ref = 1;
	
	assert(p->page->flags & PAGE_FLAG_FREE);
	
	p->page->flags &= ~PAGE_FLAG_FREE;
	ret = p->page;

	used_pages++;
	::used_pages++;

out:
	spin_unlock_irqrestore(&node_lock, cpu_flags);
	return ret;
}

struct page *page_node::allocate_pages(size_t nr_pgs, unsigned long flags)
{
	struct page *plist = NULL;
	struct page *ptail = NULL;

	for(size_t i = 0; i < nr_pgs; i++)
	{
		struct page *p = alloc_page(flags);

		if(!p)
		{
			if(plist)
				free_pages(plist);

			return NULL;
		}

		if(page_should_zero(flags))
		{
			set_non_temporal(PAGE_TO_VIRT(p), 0, PAGE_SIZE);
		}

		if(!plist)
		{
			plist = ptail = p;
		}
		else
		{
			ptail->next_un.next_allocation = p;
			ptail = p;
		}
	}

	//printf("alloc pages %lu = %p, %p\n", nr_pgs, page_to_phys(plist), __builtin_return_address(0));

	return plist;
}

struct page *page_arena::alloc_contiguous(size_t nr_pgs, unsigned long flags)
{
	unsigned long start = (unsigned long) start_arena;
	unsigned long end = (unsigned long) end_arena & -(PAGE_SIZE - 1);
	auto current = start;
	struct page *first_page = nullptr;

	unsigned long contig_in_row = 0;

	while(current != end)
	{
		struct page *p = phys_to_page(current);

		if(flags & PAGE_ALLOC_4GB_LIMIT && current >= ADDRESS_4GB_MARK)
			return nullptr;

		if(!(p->flags & PAGE_FLAG_FREE))
		{
			contig_in_row = 0;
			first_page = nullptr;
		}
		else
		{
			contig_in_row++;
			
			if(!first_page) first_page = p;
			assert(p->ref == 0);
		}

		if(contig_in_row == nr_pgs)
			break;
		
		current += PAGE_SIZE;
	}

	if(contig_in_row != nr_pgs)
		return nullptr;

	struct page *before = nullptr;

	for(size_t i = 0; i < nr_pgs; i++)
	{
		auto page = first_page + i;
		auto page_list_struct = (page_list *) PAGE_TO_VIRT(page);
		list_remove(&page_list_struct->list_node);
		page->flags &= ~PAGE_FLAG_FREE;

		page_ref(page);

		if(before)
			before->next_un.next_allocation = page;
		
		before = page;
	}

	used_pages += nr_pgs;
	::used_pages += nr_pgs;

	if(page_should_zero(flags))
	{
		set_non_temporal(PAGE_TO_VIRT(first_page), 0, nr_pgs << PAGE_SHIFT);
	}

	return first_page;
}

struct page *page_node::alloc_contiguous(size_t nr_pgs, unsigned long flags)
{	
	struct page *pages = nullptr;
	unsigned long cpu_flags = spin_lock_irqsave(&node_lock);

	list_for_every(&arena_list)
	{
		page_arena *arena = container_of(l, page_arena, arena_list_node);

		if(flags & PAGE_ALLOC_4GB_LIMIT && (unsigned long) arena->start_arena >= ADDRESS_4GB_MARK)
			goto out;
		pages = arena->alloc_contiguous(nr_pgs, flags);

		if(pages)
			goto out;
	}

out:
	spin_unlock_irqrestore(&node_lock, cpu_flags);
	return pages;
}

struct page *alloc_pages(size_t nr_pgs, unsigned long flags)
{
	auto &node = main_node;

	/* Optimise for the possibility that someone's looking to allocate '1' contiguous page */
	if(unlikely(flags & PAGE_ALLOC_CONTIGUOUS && nr_pgs > 1))
		return node.alloc_contiguous(nr_pgs, flags);
	else
		return node.allocate_pages(nr_pgs, flags);
}

void __reclaim_page(struct page *new_page)
{
	__sync_add_and_fetch(&nr_global_pages, 1);

	/* We need to set new_page->ref to 1 as free_page will decrement the ref as to
	 * free it
	*/
	new_page->ref = 1;
	free_page(new_page);
}

void page_node::free_page(struct page *p)
{
	unsigned long cpu_flags = spin_lock_irqsave(&node_lock);

	/* Reset the page */
	p->flags = 0;
	p->cache = nullptr;
	p->next_un.next_allocation = nullptr;
	p->ref = 0;

	p->flags |= PAGE_FLAG_FREE;

	auto page_list_node = (struct page_list *) PAGE_TO_VIRT(p);
	page_list_node->page = p;

	/* Add it at the beginning since it might be fresh in the cache */
	list_add(&page_list_node->list_node, &page_list);

	used_pages--;
	::used_pages--;
	
	spin_unlock_irqrestore(&node_lock, cpu_flags);
}
