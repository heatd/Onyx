/*----------------------------------------------------------------------
 * Copyright (C) 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdlib.h>
#include <string.h>
#include <errno.h>
char *strdup(const char *s)
{
	char *new_string = malloc(strlen(s) + 1);
	if(!new_string)
		return errno = ENOMEM, NULL;
	strcpy(new_string, s);
	return new_string;
}
