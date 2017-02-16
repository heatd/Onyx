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
#include <stddef.h>
#include <stdint.h>
#include "stdio_impl.h"
#include <stdio.h>
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	return __stdio_read(ptr, size, nmemb, stream);
}
