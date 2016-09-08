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
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#ifdef __is_spartix_kernel
#include <kernel/heap.h>
#endif
#include <math.h>
#ifndef __is_spartix_kernel
typedef struct block
{
	size_t size;
	struct block *next_free;
	char data[0];
} block_t;
typedef struct bucket
{
	size_t sizeof_bucket;
	size_t size_elements;
	block_t *closest_free_block;
	struct bucket *next;
} bucket_t;
size_t bucket0, bucket1, bucket2, bucket3, bucket4;
bucket_t *buckets[5];
void *heap_malloc(size_t size)
{
	_Bool merge_existing = 0;
	
	size_t new_size = bucket4;
	if(size <= bucket0) new_size = llabs(bucket0 - size) < llabs(size - new_size) ? bucket0 : new_size;
	if(size <= bucket1) new_size = llabs(bucket1 - size) < llabs(size - new_size) ? bucket1 : new_size;
	if(size <= bucket2) new_size = llabs(bucket2 - size) < llabs(size - new_size) ? bucket2 : new_size;
	if(size <= bucket3) new_size = llabs(bucket3 - size) < llabs(size - new_size) ? bucket3 : new_size;
	if(size <= bucket4) new_size = llabs(bucket4 - size) < llabs(size - new_size) ? bucket4 : new_size;
	size_t block_size = new_size;
	if(block_size == bucket4 && size > bucket4)
		block_size = size;
	size_t bucket_index = 0;
	if(block_size == bucket0) bucket_index = 0;
	if(block_size == bucket1) bucket_index = 1;
	if(block_size == bucket2) bucket_index = 2;
	if(block_size == bucket3) bucket_index = 3;
	if(size > bucket4) bucket_index = 0xFFFFF;
	if(block_size == bucket4) bucket_index = 4;
	size_t bucket_indexn = bucket_index;
	if(bucket_indexn == 0xFFFFF)
	{
		merge_existing = 1;
		bucket_indexn = 4;
	}
	bucket_t *bucket = buckets[bucket_indexn];
	if(merge_existing)
	{
		size_t num_contig_blocks = size / bucket4;
		if(size % bucket4) num_contig_blocks++;
		block_t *search = bucket->closest_free_block;
		size_t contig_blocks_found = 0;
		block_t *first_block = NULL;
		for(size_t i = 0; i < bucket->sizeof_bucket / bucket->size_elements; i++)
		{
			if(search->size == 0)
			{	first_block = search;
				contig_blocks_found++;
				if(num_contig_blocks == contig_blocks_found)
					goto ret;
			}
			else
			{
				contig_blocks_found = 0;
				first_block = NULL;
			}
			search = (block_t*)
				((char*)(search+1) + bucket->size_elements);
		}
	ret:
		first_block->size = size;
		return &first_block->data;
	}
	block_t *block = bucket->closest_free_block;
	block_t *search = bucket->closest_free_block;

	block->size = block_size;
	
	for(size_t i = 0; i < bucket->sizeof_bucket / bucket->size_elements; i++)
	{
		if(search->size == 0)
		{
			bucket->closest_free_block = search;
			break;
		}
		search = (block_t*)
			((char*)(search+1) + bucket->size_elements);
	}
	/*if(!bucket->closest_free_block) Extend();*/
	return &block->data;
}
void heap_free(void *address)
{
	block_t *block = (block_t*)((char *)(address) - sizeof(block_t));
	size_t block_size = block->size;
	size_t bucket_index = 0;
	if(block_size == bucket0) bucket_index = 0;
	if(block_size == bucket1) bucket_index = 1;
	if(block_size == bucket2) bucket_index = 2;
	if(block_size == bucket3) bucket_index = 3;
	if(block_size > bucket4) bucket_index = 0xFFFFF;
	if(block_size == bucket4) bucket_index = 4;

	size_t idx = bucket_index;
	if(idx == 0xFFFFF)
	{
		if(block_size < bucket4)
		{
			return; // Invalid pointer, just return (delete would throw an exception here)
		}
		size_t num_contig_blocks = block_size / bucket4;
		if(block_size % bucket4) num_contig_blocks++;
		bucket_t *bucket = buckets[4];
		block_t *blck = block;
		for(size_t i = 0; i < num_contig_blocks; i++)
		{
			blck->size = 0;
			blck = (block_t*)
				((char*)(blck+1) + bucket->size_elements);
		}
		idx = 4;
	}
	bucket_t *bucket = buckets[idx];
	if((char *)(bucket->closest_free_block) - (char *)(bucket) 
	> (char *)(block) - (char *)(bucket))
	{
		block->next_free = bucket->closest_free_block;
		bucket->closest_free_block = block;
	}
	block->size = 0;
}
#define bucket0s 16
#define bucket1s 64
#define bucket2s 128
#define bucket3s 256
#define bucket4s 512
int malloc_init() 
{
	bucket0 = bucket0s;
	bucket1 = bucket1s;
	bucket2 = bucket2s;
	bucket3 = bucket3s;
	bucket4 = bucket4s;
	if(!(buckets[2] = (bucket_t *)(mmap(NULL, 0x400000, PROT_WRITE, MAP_ANONYMOUS, 0, 0))))
		_exit(1);
	buckets[2]->sizeof_bucket = 0x400000; // 4 MiB by default, maybe add another constructor
	buckets[2]->size_elements = bucket2;
	buckets[2]->closest_free_block = (block_t *)((char *)(buckets[2]) + sizeof(bucket_t));
	
	if(!(buckets[3] = (bucket_t *)(mmap(NULL, 0x400000, PROT_WRITE, MAP_ANONYMOUS, 0, 0))))
		_exit(1);
	buckets[3]->sizeof_bucket = 0x400000;
	buckets[3]->size_elements = bucket3;
	buckets[3]->closest_free_block = (block_t *)((char *)(buckets[3]) + sizeof(bucket_t));
	if(!(buckets[4] = (bucket_t *)(mmap(NULL, 0x400000, PROT_WRITE, MAP_ANONYMOUS, 0, 0))))
		_exit(1);
	buckets[4]->sizeof_bucket = 0x400000;
	buckets[4]->size_elements = bucket4;
	buckets[4]->closest_free_block = (block_t *)((char *)(buckets[4]) + sizeof(bucket_t));
	if(!(buckets[0] = (bucket_t *)(mmap(NULL, 0x400000, PROT_WRITE, MAP_ANONYMOUS, 0, 0))))
		_exit(1);
	buckets[0]->sizeof_bucket = 0x400000;
	buckets[0]->size_elements = bucket0;
	buckets[0]->closest_free_block = (block_t *)((char *)(buckets[0]) + sizeof(bucket_t));
	if(!(buckets[1] = (bucket_t *)(mmap(NULL, 0x400000, PROT_WRITE, MAP_ANONYMOUS, 0, 0))))
		_exit(1);
	buckets[1]->sizeof_bucket = 0x400000;
	buckets[1]->size_elements = bucket1;
	buckets[1]->closest_free_block = (block_t *)((char *)(buckets[1]) + sizeof(bucket_t));
	return 0;
}
static _Bool is_init = 0;
#endif
void *malloc(size_t size)
{
	#ifndef __is_spartix_kernel
	if(!is_init)
		malloc_init();
	#endif
	return heap_malloc(size);
}
void free(void *ptr)
{
	return heap_free(ptr);
}
void *calloc(size_t nmemb, size_t size)
{
	void *mem = malloc(size * nmemb);
	if(!mem)
		return NULL;
	memset(mem, 0, size * nmemb);
	return mem;
}
void *realloc(void *ptr, size_t newsize)
{
	void *newbuf = malloc(newsize);
	block_t *block = (block_t*)((char*)(ptr) - sizeof(block_t));
	size_t block_size = block->size;
	memcpy(newbuf, ptr , block_size);
	free(ptr);
	return newbuf;
}