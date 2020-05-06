/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <stddef.h>

#define CONST1          ((size_t) 0x0101010101010101ULL)
#define CONST2          ((size_t) 0x8080808080808080ULL)

#define WORD_SIZE           (sizeof(size_t) / CHAR_BIT)
#define ALIGNED(x, y)       !((unsigned long) x & (y - 1))
#define HASZERO(v)          (((v) - CONST1) & ~(v) & CONST2)


typedef size_t __attribute__((__may_alias__)) word_t;

extern "C"
size_t strlen(const char *s)
{
	auto start = s;

	while(!ALIGNED(s, WORD_SIZE))
	{
		if(!*s)
			return s - start;
		s++;
	}

	auto ptr = reinterpret_cast<const word_t *>(s);
	
	for(; !HASZERO(*ptr); ptr++);
	
	s = (const char *) ptr;
	for(; *s; s++);
	return s - start;
}
