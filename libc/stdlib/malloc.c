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
#include <math.h>
#include "dlmalloc.c"
#ifdef __is_spartix_kernel
char *heap = (char*) 0xFFFFFFF890000000;
void *sbrk(unsigned long long increment)
{
	void *ret = heap;
	heap+=increment;
	return ret;
}
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	void *ret = heap;
	heap += (length + 4096) & 0xFFFFFFFFFFFFF000; 
	(void) addr;
	(void) prot;
	(void) flags;
	(void) fd;
	(void) offset;
	return ret;
}
int munmap(void *addr, size_t length)
{
	(void) addr;
	(void) length;
	return 0;
}
#endif
