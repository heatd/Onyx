/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <string.h>

int memcmp(const void *aptr, const void *bptr, size_t size)
{
	const unsigned char *a = (const unsigned char *) aptr;
	const unsigned char *b = (const unsigned char *) bptr;
	size_t i;
	for ( i = 0; i < size; i++)
		if (a[i] < b[i])
			return -1;
		else if (b[i] < a[i])
			return 1;
	return 0;
}
