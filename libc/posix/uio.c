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
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/uio.h>

#pragma GCC push_options
#pragma GCC diagnostic ignored "-Wunused-parameter"
ssize_t readv(int fd, const struct iovec *v, int veccount)
{
	return -1;
}
ssize_t writev(int fd, const struct iovec *v, int veccount)
{
	return -1;
}
ssize_t preadv(int fd, const struct iovec *v, int veccount, off_t offset)
{
	return -1;
}
ssize_t pwritev(int fd, const struct iovec *v, int veccount, off_t offset)
{
	return -1;
}
#pragma GCC pop_options
