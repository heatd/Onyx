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
/* Concatenate the NULL-terminated string src onto the end of dest, and return dest. */
char *strcat(char * restrict dest, const char * restrict src)
{
	char *ret = dest;

	while(*dest != '\0')
		dest++;
	while(*src != '\0')
		*dest++ = *src++; 

	*dest = '\0';
	
	return ret;
}
