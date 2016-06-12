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
#include <stdlib.h>
#include <string.h>

void *realloc(void *ptr, size_t new_size)
{
	void *newptr = malloc(new_size);
	memcpy(newptr, ptr, new_size); // Just copy it all
	free(ptr);
	return newptr;
}
