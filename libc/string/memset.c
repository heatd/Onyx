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
#include <string.h>
#include <stdint.h>
void *memset(void *bufptr, int value, size_t size)
{
	unsigned char *b = bufptr;
	for(size_t s = 0; s < size; s++)
		*b++ = value;
	return bufptr;
}
