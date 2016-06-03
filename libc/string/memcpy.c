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
#include <stdint.h>
void *memcpy(void *__restrict__ dstptr, const void *__restrict__ srcptr,
	     size_t size)
{
	size_t bigblocks = size / 8;
	size_t gran = size % 8;
	uint64_t *dst64 = (uint64_t *) dstptr;
	const uint64_t *src64 = (const uint64_t *) srcptr;
	unsigned char *dst = (unsigned char *) dstptr + bigblocks * 8;
	const unsigned char *src = (const unsigned char *) srcptr + bigblocks * 8;
	for(size_t i = 0; i < bigblocks; i++)
	{
		dst64[i] = src64[i];
	}
	for(size_t i = 0; i < gran; i++)
	{
		dst[i] = src[i];
	}
	return dstptr;
}
