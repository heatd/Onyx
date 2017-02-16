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
#include <ctype.h>
/* Damn thats a long macro name... */
#define ASCII_DIFF_BETWEEN_LOWER_AND_UPPER 32
int tolower(int c)
{
	/* If the ascii character code is between 91 and 64, its uppercase */
	if(c < 91 && c > 64) {
		return c + ASCII_DIFF_BETWEEN_LOWER_AND_UPPER;
	}
	return c;
}
int toupper(int c)
{
	if(c > 96 && c < 123) {
		return c - ASCII_DIFF_BETWEEN_LOWER_AND_UPPER;
	}
	return c;
}
int _toupper(int c)
{
	return toupper(c);
}
int _tolower(int c)
{
	return tolower(c);
}
int isalpha(int c)
{
	if(c > 64 && c < 123)
		return 1;
	return 0;
}
int isalnum(int c)
{
	if(isnum(c) || isalpha(c))
		return 1;
	return 0;	
}
