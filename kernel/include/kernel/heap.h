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
struct malloc_header
{
	size_t size;
	struct malloc_header *next;
	char data[0];
};
void heap_init(void *address, size_t bucket0, size_t bucket1, size_t bucket2, size_t bucket3, size_t bucket4);
void *heap_malloc(size_t size);
void heap_free(void *ptr);
#endif
