/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
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

int isnum(int c)
{
	if(c >= 48 && c <= 57)
		return 1;
	return 0;
}

int isalnum(int c)
{
	if(isnum(c) || isalpha(c))
		return 1;
	return 0;	
}

int isxdigit(int c)
{
	return isdigit(c) || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}
