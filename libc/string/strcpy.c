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
/* Copy the NULL-terminated string src into dest, and return dest. */
char *strcpy(char *dest, const char *src)
{
	char *ret = dest;
	while(*src != '\0')
		*dest++ = *src++;
	*dest = '\0';
	return ret;
}
char *strncpy(char *dest, const char *src, size_t n)
{
	char *ret = dest;
	while(n)
	{
		*dest++ = *src++;
		n--;
	}
	*dest = '\0';
	return ret;
}
