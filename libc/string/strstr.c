/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <string.h>
char *strchr(const char *str, int c)
{
	return memchr(str, c, strlen(str));
}