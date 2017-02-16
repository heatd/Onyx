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

char *stpcpy(char *restrict s1, const char *restrict s2)
{
	char *restrict dst = s1;
	const char *restrict src = s2;
	while(*src != '\0')
	{
		*dst++ = *src++;
	}
	return dst;
}