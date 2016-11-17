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
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "stdio_impl.h"
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/uio.h>
size_t __stdio_write(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	int fd = stream->fd;
	size_t passed_size = size * nmemb;
	size_t ret = write(fd, (void*) ptr, passed_size);
	return ret;
}
size_t __stdio_read(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	int fd = stream->fd;
	/*if(size > stream->buf_size)
	{
		stream->buf = malloc(size);
		memset(stream->buf, 0, size);
		FIX MALLOC(3)!!!
		stream->buf = (void*) ptr;
	}
	*/
	struct iovec v[2] = {0};
	size_t passed_size = size * nmemb;
	v[0].iov_base = (void*) ptr;
	v[0].iov_len = passed_size;
	v[1].iov_base = (void*) ptr;
	v[1].iov_len = passed_size;
	size_t r = readv(fd, v, 2);
	return r;
}