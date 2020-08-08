/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_UTILS_H
#define _ONYX_UTILS_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void *memdup(void *ptr, size_t size);
void *copy_page(void *vaddr, void *p2);
void *copy_page_to_page(void *p1, void *p2);

#ifdef __cplusplus
}
#endif

#define container_of(ptr, type, member)	\
((type *) ((char*) ptr - offsetof(type, member)))

#ifndef __cplusplus
#define min(x, y) (x < y ? x : y)
#else

template <typename Type>
Type min(Type t1, Type t2)
{
	return t1 < t2 ? t1 : t2;
}

#endif

static inline bool array_overflows(size_t n, size_t elem_size)
{
	return n > (size_t) -1 / elem_size;
}

#ifdef __cplusplus
/* Handy define for functions that can totally be constexpr in C++ */
#define CONSTEXPR constexpr

template <typename Type>
static inline bool array_overflows(size_t n)
{
	return array_overflows(n, sizeof(Type));
}

#else

#define CONSTEXPR

#endif

#define __stringify(str) #str
#define stringify(str)   __stringify(str)

#endif
