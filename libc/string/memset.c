/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <string.h>
#include <stdint.h>
void *memset(void *bufptr, int value, size_t size)
{
	unsigned char *b = bufptr;
	for(size_t s = 0; s < size; s++)
		*b++ = value;
	return bufptr;
}
