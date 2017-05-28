/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <string.h>
#include <stdlib.h>

#include <kernel/utils.h>
void *memdup(void *ptr, size_t size)
{
	void *new_ptr = malloc(size);
	if(!new_ptr)
		return NULL;
	memcpy(new_ptr, ptr, size);
	return new_ptr;
}
