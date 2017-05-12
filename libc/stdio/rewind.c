/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stddef.h>
#include <stdint.h>
#include "stdio_impl.h"
#include <stdio.h>
void rewind(FILE *stream)
{
	__stdio_rewind(stream);
}
