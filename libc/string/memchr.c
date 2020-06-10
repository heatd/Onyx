/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <string.h>

void *memchr(const void *str, int c, size_t n)
{
	char* string = (void*) str;
	for(size_t i = 0; i < n; i++) {
		if(*string == c) {
			return string;
		}
		string++;
	}
	return NULL;
}
