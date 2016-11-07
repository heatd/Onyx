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
#include <sys/uio.h>

ssize_t readv(int fd, const struct iovec *v, int veccount)
{
	syscall(SYS_readv, fd, v, veccount);
	if(rax == (unsigned long long) -1)
	{
		set_errno();
	}
	return (ssize_t)rax;
}
ssize_t writev(int fd, const struct iovec *v, int veccount)
{
	syscall(SYS_writev, fd, v, veccount);
	if(rax == (unsigned long long) -1)
	{
		set_errno();
	}
	return (ssize_t)rax;
}
ssize_t preadv(int fd, const struct iovec *v, int veccount, off_t offset)
{
	syscall(SYS_preadv, fd, v, veccount, offset);
	if(rax == (unsigned long long) -1)
	{
		set_errno();
	}
	return (ssize_t)rax;
}
ssize_t pwritev(int fd, const struct iovec *v, int veccount, off_t offset)
{
	syscall(SYS_pwritev, fd, v, veccount, offset);
	if(rax == (unsigned long long) -1)
	{
		set_errno();
	}
	return (ssize_t)rax;
}
