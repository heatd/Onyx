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
#include "dlmalloc.c"
#else
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
	if(!ptr)
		return malloc(newsize);
	void *newbuf = malloc(newsize);
	block_t *block = (block_t*)((char*)(ptr) - sizeof(block_t));
	size_t block_size = block->size;
	memcpy(newbuf, ptr , block_size);
	free(ptr);
	return newbuf;
}
#endif
