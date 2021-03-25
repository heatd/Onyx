/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <string.h>
#include <stdint.h>

void *memcpy(void *__restrict__ dstptr, const void *__restrict__ srcptr, size_t size)
{
	char *__restrict__ d = dstptr;
	const char * __restrict__ s = srcptr;
	for(size_t i = 0; i < size; i++)
	{
		*d++ = *s++;
	}

	return dstptr;
}
