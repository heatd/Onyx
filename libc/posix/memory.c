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
#include <stdlib.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mman.h>

#pragma GCC push_options
#pragma GCC diagnostic ignored "-Wunused-parameter"
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	
	return (void*) MAP_FAILED;
}
int munmap(void *addr, size_t length)
{
	return (int) -1;
}
int mprotect(void *addr, size_t len, int prot)
{
	return (int) -1;
}
uint64_t brk(void *addr)
{
	return 0;
}
#pragma GCC pop_options
#pragma GCC push_options
#pragma GCC optimize("O0")
static char *current_position = NULL;
void *sbrk(unsigned long long incr)
{
	if(current_position == NULL)
	{
		current_position = (void*)brk(NULL);
		char *ret = current_position;
		current_position += incr;
		return ret;
	}
	else if(((uint64_t)current_position % 4096) == 0)
	{
		current_position = mmap(NULL, 4096, PROT_WRITE | PROT_READ, MAP_ANONYMOUS, 0, 0);
		brk(current_position);
		char *ret = current_position;
		current_position += incr;
		return ret;
	}
	else
	{
		char *ret = current_position;
		current_position +=incr;
		return ret;
	}
}
#pragma GCC pop_options
