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
#include "stdio_impl.h"
#include <string.h>
#include <stdarg.h>

int fprintf(FILE* file, const char* string, ...)
{
	va_list varg;
	va_start(varg, string);
	char buffer[strlen(string) + 250];
	vsprintf(buffer, string, varg);
	va_end(varg);
	return fwrite((const void*) &buffer, strlen(buffer), sizeof(char), file);
}

