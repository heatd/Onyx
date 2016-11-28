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
#include <unistd.h>

#include "stdio_impl.h"

#include <sys/syscall.h>
#include <sys/uio.h>
FILE *__stdio_open(const char *path, const char *attrb)
{
	FILE *file = malloc(sizeof(FILE));
	memset(file, 0, sizeof(FILE));
	(void) attrb;
	file->fd = open(path, 0); // Fix this to use open(3)'s attributes (see POSIX.1-2008), still needs support in the kernel
	if(file->fd == -1)
	{
		free(file);
		return NULL;
	}
	return file;
}
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
	if(size > stream->buf_size)
	{
		if(stream->buf)
			free(stream->buf);
		stream->buf = malloc(size);
		if(!stream->buf)
			exit(EXIT_FAILURE);
		memset(stream->buf, 0, size);
	}
	struct iovec v[2] = {0};
	size_t passed_size = size * nmemb;
	v[0].iov_base = (void*) stream->buf;
	v[0].iov_len = passed_size;
	v[1].iov_base = (void*) ptr;
	v[1].iov_len = passed_size;
	size_t r = readv(fd, v, 2);
	return r;
}
int __stdio_fseek(FILE *stream, long offset, int whence)
{
	off_t off = lseek(stream->fd, offset, whence);
	if(off == (off_t) -1)
	{
		return -1;
	}
	stream->off = off;
	return 0;
}
long __stdio_ftell(FILE *stream)
{
	return stream->off;
}
void __stdio_rewind(FILE *stream)
{
	lseek(stream->fd, 0, SEEK_SET);
	stream->off = 0;
}
char *__stdio_gets(char *buf)
{
	size_t size = STDIO_DEFAULT_GETS_SIZE;
	if(size > stdin->buf_size)
	{
		if(stdin->buf)
			free(stdin->buf);
		stdin->buf = malloc(size);
		if(!stdin->buf)
			exit(EXIT_FAILURE);
		memset(stdin->buf, 0, size);
	}
	ssize_t r = read(stdin->fd, stdin->buf, stdin->buf_size);
	memcpy(buf, stdin->buf, r);
	return buf;
}
int __stdio_close(FILE *file)
{
	close(file->fd);
	free(file->buf);
	free(file);
	return 0;
}
