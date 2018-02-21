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
	spinlock_t lock;
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

	acquire_spinlock(&arena->lock);
	if(arena->free_pages < nr_pages)
	{
		release_spinlock(&arena->lock);
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
		release_spinlock(&arena->lock);
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

		release_spinlock(&arena->lock);

		return (void*) base - PHYS_BASE;
	}
}

void *page_alloc(size_t nr_pages, unsigned long flags)
{
	void *pages = NULL;
	for_every_arena(&main_cpu)
	{
		if((pages = page_alloc_from_arena(nr_pages, flags, arena)) != NULL)
		{
			memset(PHYS_TO_VIRT(pages), 0, nr_pages << PAGE_SHIFT);
			return pages;
		}
	}

	return NULL;
}

void page_free_pages(struct page_arena *arena, void *addr, size_t nr_pages)
{
	acquire_spinlock(&arena->lock);

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

	release_spinlock(&arena->lock);
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

static void page_add(struct page_list **list, void *__page)
{
	struct page_list *page = PHYS_TO_VIRT(__page);
	page->next = NULL;

	if(*list)
	{
		while(*list)
			list = &(*list)->next;
		page->prev = (struct page_list *) ((char*) list - 
			offsetof(struct page_list, next));
	}
	else
		page->prev = NULL;
	*list = page;
}

static void append_arena(struct page_cpu *cpu, struct page_arena *arena)
{
	struct page_arena **a = &cpu->arenas;

	while(*a)
		a = &(*a)->next;
	*a = arena;
}

uintptr_t min(uintptr_t x, uintptr_t y);

static void page_add_region(stack_entry_t *entry)
{
	size_t size = entry->size;
	uintptr_t base = entry->base;
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
			page_add(&arena->page_list, (void*) (base + i));
		}

		append_arena(&main_cpu, arena);

		size -= area_size;
		base += area_size;
	}
}

void page_init(void)
{
	size_t nentries = 0;
	size_t mem_size = bootmem_get_memsize();
	size_t nr_arenas = mem_size / 0x200000;
	void *ptr = bootmem_alloc(vmm_align_size_to_pages(nr_arenas * sizeof(struct page_arena)));
	__kbrk(PHYS_TO_VIRT(ptr));
	stack_t *stack = bootmem_get_pstack(&nentries);

	for(size_t i = 0; i < nentries; i++)
	{
		if(stack->next[i].base != 0 && stack->next[i].size != 0)
		{
			printf("Region %lu: %016lx-%016lx\n", i, stack->next[i].base,
			stack->next[i].base + stack->next[i].size);
			page_add_region(&stack->next[i]);
		}
	}

	page_is_initialized = true;
}

void *__alloc_pages(int order)
{
	if(page_is_initialized == false)
		return bootmem_alloc(1);
	size_t nr_pages = pow2(order);

	return page_alloc(nr_pages, 0);
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

struct page *get_phys_pages(int order)
{
	void *addr = __alloc_pages(order);
	
	size_t nr_pages = pow2(order);
	if(!addr)
		return NULL;

	uintptr_t paddr = (uintptr_t) addr;

	struct page *ret = phys_to_page(paddr);

	for(; nr_pages; nr_pages--)
	{
		page_increment_refcount((void*) paddr);
	}
	return ret;
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
