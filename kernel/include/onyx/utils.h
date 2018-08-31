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

#define container_of(ptr, type, member)	\
((type *) ((char*) ptr - offsetof(type, member)))

#define min(x, y) (x < y ? x : y)

#ifdef __cplusplus
}
#endif
#endif
