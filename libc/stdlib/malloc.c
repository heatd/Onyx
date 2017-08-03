/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include "dlmalloc.c"
#ifdef __is_onyx_kernel
#include <kernel/vmm.h>
extern _Bool is_initialized;
char *heap = (char*) 0xFFFFFFF890000000;
char *heap_limit = (char*) 0xFFFFFFF890400000;
int heap_expand(void)
{
	/* Allocate 256 pages */
	if(!vmm_map_range(heap_limit, 256, VM_WRITE | VM_GLOBAL | VM_NOEXEC))
		return -1;
	heap_limit += 0x100000;
	return 0;
}
void *sbrk(intptr_t increment)
{
	if(heap + increment >= heap_limit || heap >= heap_limit)
	{
		if(heap_expand() < 0)
			return NULL;
	}
	void *ret = heap;
	heap += increment;

	return ret;
}
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	void *ret;
	(void) addr;
	(void) prot;
	(void) flags;
	(void) fd;
	(void) offset;

	if(is_initialized == 0)
	{
		ret = heap;
		heap += (length + 4096) & 0xFFFFFFFFFFFFF000; 
	}
	else
		ret = vmalloc(vmm_align_size_to_pages(length), VM_TYPE_HEAP, VM_WRITE | VM_NOEXEC | VM_GLOBAL);
	return ret;
}
int munmap(void *addr, size_t length)
{
	(void) addr;
	(void) length;
	return 0;
}
void *zalloc(size_t size)
{
	return calloc(1, size);
}
#endif
