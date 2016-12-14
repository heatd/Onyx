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
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>

#include <kernel/heap.h>
#include <kernel/vmm.h>
#include <kernel/spinlock.h>
#include <kernel/log.h>
struct malloc_header *free_list = NULL;
static size_t heap_size = 0;
static spinlock_t heap_lock;
static size_t heap_used_memory = 0;
inline size_t heap_align_size(size_t orig)
{
	return (orig + 16) & ~0xF;
}
struct malloc_header *heap_expand()
{
	/* TODO */
	return NULL;
}
inline size_t heap_get_contig_blocks_from_size(size_t size, size_t block_size)
{
	size_t b = size / block_size;
	return b;
}
struct malloc_header *heap_find_free_blocks(size_t size)
{	
	size_t aligned_size = heap_align_size(size);	
	if(!free_list)
		free_list = heap_expand(); /* If free_list == NULL, expand the heap */
	size_t block_size = free_list->size;

	/* Get the number of contiguous blocks needed for this allocation */
	size_t contig_blocks = heap_get_contig_blocks_from_size(aligned_size, block_size);

	struct malloc_header *h = free_list;
	struct malloc_header *first_header = NULL;
	struct malloc_header *last_header = NULL;

	size_t blocks_found = 0;
	for(size_t i = 0; i < heap_size; i += sizeof(struct malloc_header) + h->size)
	{
		if(blocks_found == contig_blocks)
		{
			h = first_header;
			printf("h->next: %p\n", h->next);
			for(ssize_t j = contig_blocks; j >= 0; j--)
			{
				struct malloc_header *d = h->next;
				if(j == 0) free_list = h->next;
				h->next = NULL;
				h = d;
			}
			return first_header;
		}
		if(blocks_found)
		{
			if((char*) &last_header->data + last_header->size != h)
			{
				blocks_found = 1;
				last_header = h;
				first_header = h;
				continue;
			}
		}
		if(!last_header)
			last_header = h;
		if(!first_header)
			first_header = h;
		blocks_found++;
		h = h->next;
	}
	return NULL;
}
size_t heap_get_used_memory()
{
	printf("%x\n", heap_used_memory);
	return heap_used_memory;
}
void *heap_malloc(size_t t)
{
	/* Acquire the spinlock */
	acquire_spinlock(&heap_lock);

	struct malloc_header *ret = heap_find_free_blocks(t);
	if(!ret)
	{
		release_spinlock(&heap_lock);
		return NULL;
	}
	ret->size = heap_align_size(t);
	heap_used_memory += ret->size;
retur:
	release_spinlock(&heap_lock);
	return ret+1;
}
void heap_free(void *f)
{}
void heap_search(uintptr_t pt)
{}
void heap_fill(struct malloc_header *hdr, size_t size, size_t block_size)
{
	for(size_t i = 0; i < size; i += sizeof(struct malloc_header) + block_size)
	{
		hdr->next = (char*) &hdr->data + block_size;
		hdr->size = block_size;
		hdr = hdr->next;
	}
}
void heap_init(void *address, size_t bucket0s, size_t bucket1s, size_t bucket2s, size_t bucket3s, size_t bucket4s) 
{
	/* Initialize the free list */
	heap_fill((struct malloc_header *) address, 0x400000, 32);
	free_list = address;
	
	heap_size = 0x400000;


	printf("Heap initialized!\n");
}
