/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
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
