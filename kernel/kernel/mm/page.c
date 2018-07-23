/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <assert.h>

#include <onyx/atomic.h>
#include <onyx/log.h>
#include <onyx/bootmem.h>
#include <onyx/page.h>
#include <onyx/vmm.h>
#include <onyx/slab.h>
#include <onyx/crc32.h>

static struct page_hashtable hashtable = {0};
static size_t num_pages = 0;
static bool are_pages_registered = false;

bool pages_are_registered(void)
{
	return are_pages_registered;
}

unsigned int page_hash(uintptr_t p)
{
	unsigned int hash = crc32_calculate((uint8_t*) &p, sizeof(uintptr_t));
	return hash % PAGE_HASHTABLE_ENTRIES;
}

static void append_to_hash(unsigned int hash, struct page *page)
{
	if(!hashtable.table[hash])
	{
		hashtable.table[hash] = page;
	}
	else
	{
		struct page *p = hashtable.table[hash];
		while(p->next) p = p->next;
		p->next = page;
	}
}

void page_add_page(void *paddr)
{
	static size_t counter = 0;
	counter++;
	unsigned int hash = page_hash((uintptr_t) paddr);
	struct page *page = __ksbrk(sizeof(struct page));

	assert(page != NULL);

	page->paddr = paddr;
	page->ref = 0;
	page->next = NULL;
	append_to_hash(hash, page);
	++num_pages;
}

void page_add_page_late(void *paddr)
{
	static size_t counter = 0;
	counter++;
	unsigned int hash = page_hash((uintptr_t) paddr);
	struct page *page = zalloc(sizeof(struct page));

	assert(page != NULL);

	page->paddr = paddr;
	page->ref = 0;
	page->next = NULL;
	append_to_hash(hash, page);
	++num_pages;
}

void page_register_pages(void)
{
	INFO("page", "Registering pages!\n");
	/*size_t nentries = 0;
	stack_t *stack = bootmem_get_pstack(&nentries);
	for(size_t i = 0; i < nentries; i++)
	{
		if(stack->next[i].base != 0 && stack->next[i].size != 0)
		{
			uintptr_t base = stack->next[i].base;
			size_t pages = stack->next[i].size / PAGE_SIZE;
			while(pages--)
			{
				page_add_page((void*) base);
				base += PAGE_SIZE;
			}
		}
	}*/
	are_pages_registered = true;
	INFO("page", "%lu pages registered, aprox. %lu bytes used\n", num_pages,
	          num_pages * sizeof(struct page));
}

struct page *phys_to_page(uintptr_t phys)
{
	unsigned int hash = page_hash(phys);
	struct page *p = hashtable.table[hash];
	for(; p; p = p->next)
	{
		if(p->paddr == (void*) phys)
			return p;
	}
	ERROR("page", "%p queried for %lx, but it doesn't exist!\n", __builtin_return_address(0), phys);
	return NULL;
}

unsigned long page_increment_refcount(void *paddr)
{
	struct page *page = phys_to_page((uintptr_t) paddr);
	assert(page != NULL);
	return atomic_inc(&page->ref, 1);
}

unsigned long page_decrement_refcount(void *paddr)
{
	struct page *page = phys_to_page((uintptr_t) paddr);
	assert(page != NULL);
	return atomic_dec(&page->ref, 1);
}

extern char kernel_start[0];
extern char kernel_end[0];

struct kernel_limits
{
	uintptr_t start_phys, start_virt;
	uintptr_t end_phys, end_virt;
};

void get_kernel_limits(struct kernel_limits *l)
{
	uintptr_t start_virt = (uintptr_t) &kernel_start;
	uintptr_t end_virt = (uintptr_t) &kernel_end;

	l->start_virt = start_virt;
	l->end_virt = end_virt;

	l->start_phys = start_virt - KERNEL_VIRTUAL_BASE;
	l->end_phys = end_virt - KERNEL_VIRTUAL_BASE;
}

bool klimits_present = false;

bool check_kernel_limits(void *__page)
{
	static struct kernel_limits l;
	uintptr_t page = (uintptr_t) __page;

	if(!klimits_present)
	{
		klimits_present = true;
		get_kernel_limits(&l);
		printf("Kernel limits: %lx-%lx phys, %lx-%lx virt\n", l.start_phys,
		l.end_phys, l.start_virt, l.end_virt);
	}

	if(page >= l.start_phys && page < l.end_phys)
		return true;
	
	return false;
}

struct used_pages *used_pages_list = NULL;

void page_add_used_pages(struct used_pages *pages)
{
	struct used_pages **pp = &used_pages_list;

	while(*pp != NULL)
		pp = &(*pp)->next;

	*pp = pages;	
}

bool platform_page_is_used(void *page);

bool page_is_used(void *__page, struct bootmodule *modules)
{
	uintptr_t page = (uintptr_t) __page;

	for(struct bootmodule *m = modules; m != NULL; m = m->next)
	{
		if(page >= m->base && m->base + m->size > page)
			return true;
	}

	for(struct used_pages *p = used_pages_list; p; p = p->next)
	{
		if(page >= p->start && p->end > page)
			return true;
	}

	if(check_kernel_limits(__page) == true)
		return true;

	return platform_page_is_used(__page);
}