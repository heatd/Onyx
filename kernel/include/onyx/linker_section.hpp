/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_LINKER_SECTION_H
#define _ONYX_LINKER_SECTION_H

#include <stddef.h>

#define DEFINE_LINKER_SECTION_SYMS(start, end) 	\
extern "C" {					\
extern unsigned char start;		       	\
extern unsigned char end;			\
}

class linker_section
{
public:
	unsigned char *start;
	unsigned char *end;
public:
	constexpr linker_section(unsigned char *__start, unsigned char *__end) : start(__start), end(__end)
	{
	}

	template <typename Type>
	Type *as()
	{
		return reinterpret_cast<Type *>(start);
	}

	size_t size()
	{
		return end - start;
	}
};

#endif
