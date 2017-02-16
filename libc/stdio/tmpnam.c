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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

static char *prefix = "/tmp/";
static char tmpnambuf[250];
char *tmpnam(char *s)
{
	memset(tmpnambuf, 0, 250);
	strcpy(tmpnambuf, prefix);
	for(int i = 0; i < 10; i++)
	{
		int c = rand() & 0x7F;
		while(isalnum(c) == 0)
		{
			c = rand() & 0x7F;
		}
		tmpnambuf[strlen(tmpnambuf)] = c;
	}
	if(s)
	{
		strcpy(s, tmpnambuf);
	}
	return tmpnambuf;
}
