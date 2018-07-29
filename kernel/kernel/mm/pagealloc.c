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
#include <onyx/vmm.h>
#include <onyx/panic.h>

size_t page_memory_size;
size_t nr_global_pages;

static inline unsigned long pow2(int exp)
{
	return (1UL << (unsigned long) exp);
}

struct page_list 
{
	struct page_list *prev;
	struct page_list *next;
};

struct page_cpu
{
	struct page_arena *arenas;
	struct processor *cpu;
	struct page_cpu *next;
};

struct page_arena
{
	unsigned long free_pages;
	unsigned long nr_pages;
	void *start_arena;
	void *end_arena;
	struct page_list *page_list;
	struct page_list *tail;
	struct spinlock lock;
	struct page_arena *next;
};

static bool page_is_initialized = false;

struct page_cpu main_cpu = {0};

#define for_every_arena(cpu)	for(struct page_arena *arena = (cpu)->arenas; arena; \
	arena = arena->next)


void *page_alloc_from_arena(size_t nr_pages, unsigned long flags, struct page_arena *arena)
{
	struct page_list *p = arena->page_list;
	size_t found_pages = 0;
	uintptr_t base = 0;
	struct page_list *base_pg = NULL;
	bool found_base = false;

	spin_lock(&arena->lock);
	if(arena->free_pages < nr_pages)
	{
		spin_unlock(&arena->lock);
		return NULL;
	}

	/* Look for contiguous pages */
	for(; p && found_pages != nr_pages; p = p->next)
	{
		if((uintptr_t) p->next - (uintptr_t) p > PAGE_SIZE && nr_pages != 1)
		{
			found_pages = 0;
			found_base = false;
			break;
		}
		else
		{
			if(found_base == false)
			{
				base = (uintptr_t) p;
				found_base = true;
			}
			++found_pages;
		}
	}

	/* If we haven't found nr_pages contiguous pages, continue the search */
	if(found_pages != nr_pages)
	{
		spin_unlock(&arena->lock);
		return NULL;
	}
	else
	{
		base_pg = (struct page_list *) base;
		struct page_list *head = base_pg->prev;
		struct page_list *tail = base_pg;

		arena->free_pages -= found_pages;

		while(found_pages--)
			tail = tail->next;

		if(head)
			head->next = tail;
		else
			arena->page_list = tail;
		
		if(tail)
			tail->prev = head;

		spin_unlock(&arena->lock);

		return (void*) base - PHYS_BASE;
	}
}

void *page_alloc(size_t nr_pages, unsigned long flags)
{
	void *pages = NULL;
	for_every_arena(&main_cpu)
	{
		if(arena->free_pages == 0)
			continue;
		if((pages = page_alloc_from_arena(nr_pages, flags, arena)) != NULL)
		{
			return pages;
		}
	}

	return NULL;
}

static void append_page(struct page_arena *arena, struct page_list *page)
{
	if(!arena->page_list)
	{
		arena->page_list = arena->tail = page;
		page->next = NULL;
		page->prev = NULL;
	}
	else
	{
		arena->tail->next = page;
		page->prev = arena->tail;
		arena->tail = page;
		page->next = NULL;
	}
}

void page_free_pages(struct page_arena *arena, void *addr, size_t nr_pages)
{
	spin_lock(&arena->lock);

	if(!arena->page_list)
	{
		struct page_list *list = NULL;
		uintptr_t b = (uintptr_t) addr;
		for(size_t i = 0; i < nr_pages; i++, b += PAGE_SIZE)
		{
			struct page_list *l = PHYS_TO_VIRT(b);
			l->next = NULL;
			if(!list)
			{
				arena->page_list = l;
				l->prev = NULL;
				list = l;	
			}
			else
			{
				list->next = l;
				l->prev = list;
				list = l;
			}

		}
	}
	else
	{
		struct page_list *list = arena->page_list;
		while(list->next) list = list->next;
		
		uintptr_t b = (uintptr_t) addr;
		for(size_t i = 0; i < nr_pages; i++, b += PAGE_SIZE)
		{
			struct page_list *l = PHYS_TO_VIRT(b);
			l->next = NULL;
			list->next = l;
			l->prev = list;
			list = l;
		}
	}

	spin_unlock(&arena->lock);
}

void page_free(size_t nr_pages, void *addr)
{
	for_every_arena(&main_cpu)
	{
		if((uintptr_t) arena->start_arena <= (uintptr_t) addr && 
			(uintptr_t) arena->end_arena > (uintptr_t) addr)
		{
			page_free_pages(arena, addr, nr_pages);
		}
	}
}

bool page_is_used(void *__page, struct bootmodule *modules);
size_t page_add_counter = 0;

static int page_add(struct page_arena *arena, void *__page,
	struct bootmodule *modules)
{
	if(page_is_used(__page, modules))
		return -1;
	page_add_counter++;

	struct page_list *page = PHYS_TO_VIRT(__page);
	page->next = NULL;

	append_page(arena, page);
	page_add_page(__page);

	return 0;
}

static void append_arena(struct page_cpu *cpu, struct page_arena *arena)
{
	struct page_arena **a = &cpu->arenas;

	while(*a)
		a = &(*a)->next;
	*a = arena;
}

uintptr_t min(uintptr_t x, uintptr_t y);

static void page_add_region(uintptr_t base, size_t size, struct bootmodule *module)
{
	while(size)
	{
		size_t area_size = min(size, 0x200000);
		struct page_arena *arena = __ksbrk(sizeof(struct page_arena));
		assert(arena != NULL);
		memset_s(arena, 0, sizeof(struct page_arena));

		arena->free_pages = arena->nr_pages = area_size >> PAGE_SHIFT;
		arena->start_arena = (void*) base;
		arena->end_arena = (void*) (base + area_size);

		for(size_t i = 0; i < area_size; i += PAGE_SIZE)
		{
			/* If the page is being used, decrement the free_pages counter */
			if(page_add(arena, (void*) (base + i), module) < 0)
				arena->free_pages--;
		}

		append_arena(&main_cpu, arena);

		size -= area_size;
		base += area_size;
	}
}

void page_init(size_t memory_size, void *(*get_phys_mem_region)(uintptr_t *base,
	uintptr_t *size, void *context), struct bootmodule *modules)
{
	uintptr_t region_base;
	uintptr_t region_size;
	void *context_cookie = NULL;

	printf("page: Memory size: %lu\n", memory_size);
	page_memory_size = memory_size;
	nr_global_pages = vmm_align_size_to_pages(memory_size);

	size_t nr_arenas = page_memory_size / 0x200000;
	if(page_memory_size % 0x200000)
		nr_arenas++;

	size_t needed_memory = nr_arenas *
		sizeof(struct page_arena) + 
		nr_global_pages * sizeof(struct page);
	void *ptr = alloc_boot_page(vmm_align_size_to_pages(needed_memory), 0);
	if(!ptr)
	{
		halt();
	}

	__kbrk(PHYS_TO_VIRT(ptr));


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
		page_add_region(region_base, region_size, modules);
	}

	page_is_initialized = true;
}

void *__alloc_pages_nozero(int order)
{
	if(page_is_initialized == false)
		return alloc_boot_page(1, BOOTMEM_FLAG_LOW_MEM);
	size_t nr_pages = pow2(order);

	void *p = page_alloc(nr_pages, 0);
	
	return p;
}

void *__alloc_pages(int order)
{
	void *p = __alloc_pages_nozero(order);

	size_t nr_pages = pow2(order);

	if(p)
	{
		memset(PHYS_TO_VIRT(p), 0, nr_pages << PAGE_SHIFT);
	}
	return p;
}

void *__alloc_page(int opt)
{
	return __alloc_pages(0);
}

void __free_pages(void *pages, int order)
{
	page_free(pow2(order), pages);
}

void __free_page(void *page)
{
	__free_pages(page, 0);
}

void page_get_stats(struct memstat *m){}

extern unsigned char kernel_end;

void *kernel_break = &kernel_end;

__attribute__((malloc))
void *__ksbrk(long inc)
{
	void *ret = kernel_break;
	kernel_break = (char*) kernel_break + inc;
	return ret;
}

void __kbrk(void *break_)
{
	kernel_break = break_;
}

struct page *get_phys_pages_contig(size_t nr_pgs)
{
	/*void *addr = __alloc_pages(order);
	
	size_t nr_pages = pow2(order);
	if(!addr)
		return NULL;

	uintptr_t paddr = (uintptr_t) addr;

	struct page *ret = phys_to_page(paddr);

	for(; nr_pages; nr_pages--)
	{
		page_increment_refcount((void*) paddr);
	} */
	return NULL;
}

void free_pages(struct page *pages)
{
	struct page *next = NULL;

	for(struct page *p = pages; p != NULL; p = next)
	{
		next = p->next_un.next_allocation;
		free_page(p);
	}
}

struct page *__get_phys_pages(size_t nr_pgs, unsigned long flags)
{
	struct page *plist = NULL;

	for(size_t i = 0; i < nr_pgs; i++)
	{
		struct page *p = get_phys_page();

		if(!p)
		{
			if(plist)
				free_pages(plist);
		}

		if(!plist)
		{
			plist = p;
		}
		else
		{
			struct page *i = plist;
			for(; i->next_un.next_allocation != NULL; i = i->next_un.next_allocation);
			i->next_un.next_allocation = p;
		}
	}

	return plist;
}

struct page *get_phys_pages(size_t nr_pgs, unsigned long flags)
{
	if(flags & PAGE_ALLOC_CONTIGUOUS)
		return get_phys_pages_contig(nr_pgs);
	else
		return __get_phys_pages(nr_pgs, flags);
}

struct page *get_phys_page(void)
{
	void *addr = __alloc_page(0);

	if(!addr)
		return NULL;

	struct page *p = phys_to_page((uintptr_t) addr);
	p->ref++;
	return p;
}

void free_page(struct page *p)
{
	if(page_decrement_refcount(p) == 0)
		__free_page(p->paddr);
}
