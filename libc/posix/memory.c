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
#include <unistd.h>
#include <stdlib.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mman.h>

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	(void) addr;
	(void) length;
	(void) prot;
	(void) flags;
	(void) fd;
	(void) offset;
	asm volatile("mov $11, %rax; int $0x80");
	register void *rax asm("rax");
	return rax;
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
int brk(void *addr)
{
	syscall(SYS_brk, addr);
	if(rax == (unsigned long long) -1)
	{
		set_errno();
	}
	return (int) rax;
}