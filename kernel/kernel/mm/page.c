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
#include <onyx/vm.h>
#include <onyx/slab.h>
#include <onyx/crc32.h>

static struct page_hashtable hashtable = {0};
static size_t num_pages = 0;

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

struct page *page_add_page(void *paddr)
{
	static size_t counter = 0;
	counter++;
	unsigned int hash = page_hash((uintptr_t) paddr);
	struct page *page = __ksbrk(sizeof(struct page));

	assert(page != NULL);

	page->paddr = paddr;
	page->ref = 0;
	page->next = NULL;
	page->next_un.next_allocation = NULL;
	append_to_hash(hash, page);
	++num_pages;

	return page;
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

extern char kernel_start[0];
extern char kernel_end[0];

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

void page_print_shared(void)
{
	for(unsigned int i = 0; i < PAGE_HASHTABLE_ENTRIES; i++)
	{
		for(struct page *p = hashtable.table[i]; p != NULL; p = p->next)
		{
			if(p->ref != 1 && p->ref != 0)
				printk("Page %p has ref %lu\n", p->paddr, p->ref);
		}
	}
}