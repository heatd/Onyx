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
#include <unistd.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/syscall.h>

int open(const char *path, int flags)
{
	syscall(SYS_open, path, flags);
	if(ret == (unsigned long long) -1)
	{
		set_errno();
	}
	return ret;
}
int close(int fd)
{
	syscall(SYS_close, fd);
	return ret;
}
int read(int fd, void *buf, unsigned int count)
{
	syscall(SYS_read, fd, buf, count);
	if(ret == (unsigned long long) -1)
	{
		set_errno();
	}
	return ret;
}
int write(int fd, void *buf, unsigned int count)
{
	syscall(SYS_write, fd, buf, count);
	if(ret == (unsigned long long) -1)
	{
		set_errno();
	}
	return ret;
}
unsigned long lseek(int fd, unsigned long offset, int whence)
{
	syscall(SYS_lseek, fd, offset, whence);
	if(ret == (unsigned long long) -1)
	{
		set_errno();
	}
	return ret;
}
int isatty(int fildes)
{
	syscall(SYS_isatty, fildes);
	if(ret == 0)
	{
		set_errno();
	}
	return ret;
}
int ioctl(int fd, int op, ...)
{
	va_list varg;
	va_start(varg, op);
	syscall(SYS_ioctl, fd, op, varg);
	va_end(varg);
	return rax;
}