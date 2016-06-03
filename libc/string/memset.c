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
void *memset(void *bufptr, int value, size_t size)
{
	size_t bigblocks = size / 8;
	size_t gran = size % 8;
	uint64_t *buf64 = (uint64_t *) bufptr;
	unsigned char *buf = (unsigned char *) bufptr + bigblocks * 8;
	for(size_t i = 0; i < bigblocks; i++)
	{
		buf64[i] = value;
	}
	for(size_t i = 0; i < gran; i++)
	{
		buf[i] = value;
	}
	return bufptr;
}
