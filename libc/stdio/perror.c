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
#include <errno.h>
#include <stdio.h>
#include <string.h>

void perror(const char *error_msg)
{
	const char *error = (const char*) strerror(errno);
	if(error_msg && *error_msg != '\0')
		printf("%s%s\n", error_msg, error);
	else
		printf("%s\n", error);	
}