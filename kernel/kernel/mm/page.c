/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <assert.h>

#include <onyx/log.h>
#include <onyx/bootmem.h>
#include <onyx/page.h>
#include <onyx/vmm.h>
#include <onyx/slab.h>
#include <onyx/crc32.h>

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
	unsigned int hash = page_hash((uintptr_t) paddr);
	struct page *page = malloc(sizeof(struct page));
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
	size_t nentries = 0;
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
	}
	are_pages_registered = true;
	INFO("page", "%u pages registered, aprox. %u bytes used\n", num_pages, num_pages * sizeof(struct page));
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
	ERROR("page", "%p queried for %p, but it doesn't exist!\n", __builtin_return_address(0), phys);
	return NULL;
}
unsigned long page_increment_refcount(void *paddr)
{
	struct page *page = phys_to_page((uintptr_t) paddr);
	assert(page != NULL);
	return __sync_fetch_and_add(&page->ref, 1);
}
unsigned long page_decrement_refcount(void *paddr)
{
	struct page *page = phys_to_page((uintptr_t) paddr);
	assert(page != NULL);
	return __sync_fetch_and_sub(&page->ref, 1);
}
