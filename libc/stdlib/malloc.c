/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <math.h>
#include <stdbool.h>
#include "dlmalloc.c"
#ifdef __is_onyx_kernel
#include <kernel/vmm.h>
extern _Bool is_initialized;
char *heap = (char*) 0xFFFFFFF890000000;
void *sbrk(unsigned long long increment)
{
	void *ret = heap;
	heap+=increment;
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
#endif
