/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stddef.h>
#include <stdint.h>
#include "stdio_impl.h"
#include <stdio.h>
int fseek(FILE *stream, long offset, int whence)
{
	return __stdio_fseek(stream, offset, whence);
}
