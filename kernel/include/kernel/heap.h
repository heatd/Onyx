/*
* Copyright (c) 2016 Pedro Falcato
* This file is a part of Spartix, and is released under the terms of the MIT License
* - check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_HEAP_H
#define _KERNEL_HEAP_H

#include <stdint.h>
#include <string.h>
#include <math.h>
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

void heap_init(void *address, size_t bucket0, size_t bucket1, size_t bucket2, size_t bucket3, size_t bucket4);
void *heap_malloc(size_t size);
void heap_free(void *ptr);
#endif