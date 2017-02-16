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

void *memchr(const void *str, int c, size_t n)
{
	char* string = (void*)str;
	for(size_t i = 0; i < n; i++) {
		if(*string == c) {
			return string;
		}
		string++;
	}
	return NULL;
}
