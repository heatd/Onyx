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
char* strstr(char *str, char *substr)
{
	  while (*str)
	  {
		    char *begin = str;
		    char *pattern = substr;

		    // If first character of sub string match, check for whole string
		    while (*str && *pattern && *str == *pattern)
			{
			      str++;
			      pattern++;
		    }
		    // If complete sub string match, return starting address
		    if (!*pattern)
		    	  return begin;

		    str = begin + 1;	// Increament main string
	  }
	  return 0;
}
char *strchr(char *str, int c)
{
	return memchr(str, c, strlen(str));
}