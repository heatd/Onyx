/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <string.h>

char *strchr(const char *s, int c)
{
	while(*s != c && *s != '\0')
		s++;

	if(*s == '\0')		return NULL;
	return (char *) s;
}

char *strnchr(const char *s, size_t len, int c)
{
	while(*s != c && *s != '\0' && len)
	{
		s++;
		len--;
	}

	if(len == 0 || *s == '\0')		return NULL;
	return (char *) s;
}

char *strrchr(const char *s, int c)
{
	size_t len = strlen(s);

	const char *end = s + len - 1;

	while(len--)
	{
		if (*s == c)
			return (char *) s;
		s--;
	}

	return NULL;
}
