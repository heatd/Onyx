/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
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

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	syscall(SYS_mmap, addr, length, prot, flags, fd, offset);
	if(rax == (unsigned long long) -1)
	{
		set_errno();
	}
	return (void*) rax;
}
int munmap(void *addr, size_t length)
{
	syscall(SYS_munmap, addr, length);
	if(rax == (unsigned long long) -1)
	{
		set_errno();
	}
	return (int) rax;
}
int mprotect(void *addr, size_t len, int prot)
{
	syscall(SYS_mprotect, addr, len, prot);
	if(rax == (unsigned long long) -1)
	{
		set_errno();
	}
	return (int) rax;
}
uint64_t brk(void *addr)
{
	syscall(SYS_brk, addr);
	if(rax == (unsigned long long) -1)
	{
		set_errno();
	}
	return rax;
}
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
