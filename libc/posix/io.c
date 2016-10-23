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
#include <sys/types.h>
#include <sys/syscall.h>

int open(const char *path, int flags)
{
	syscall(SYS_open, path, flags);
	return rax;
}
int read(int fd, void *buf, unsigned int count)
{
	syscall(SYS_read, fd, buf, count);
	return rax;
}
int write(int fd, void *buf, unsigned int count)
{
	syscall(SYS_write, fd, buf, count);
	return rax;
}
unsigned long lseek(int fd, unsigned long offset, int whence)
{
	syscall(SYS_lseek, fd, offset, whence);
	return rax;
}
