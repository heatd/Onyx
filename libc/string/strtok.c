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
#include <stdio.h>

char *last_string = NULL;
char *strtok(char *s, char *delim)
{
	if(!s)
		s = last_string;
	size_t len = strlen(s);
	size_t delim_len = strlen(delim);
	for(size_t i = 0; i < len; i++)
	{
		if(!memcmp(&s[i], delim, delim_len))
		{
			last_string = &s[i+1];
			return &s[i];
		}
	}
	last_string = NULL;
	return NULL;
}