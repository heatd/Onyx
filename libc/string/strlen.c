/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <string.h>
#include <stdio.h>
size_t strlen(const char *string)
{
	size_t result = 0;
	while (string[result])
		result++;

	return result;
}
