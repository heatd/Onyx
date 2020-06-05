/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _UTILS_H
#define _UTILS_H

#include <stddef.h>
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

#define __stringify(str) #str
#define stringify(str)   __stringify(str)

#endif
