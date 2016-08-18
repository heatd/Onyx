/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _STDLIB_H
#define _STDLIB_H 1

#include <sys/cdefs.h>
#include <string.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#ifndef NULL
#ifdef __cplusplus
#define NULL 0
#else
#define NULL (void*)0
#endif
#endif
int atexit(void (*)(void));
int atoi(const char*);
char* getenv(const char*);
__attribute__((__noreturn__))
void abort(void);
void free(void*);
void itoa(uint64_t i, unsigned int base, char *buf, _Bool is_upper);
void* malloc(size_t size);
void* realloc(void *ptr, size_t new_size);
void qsort(void* base_ptr,
           size_t num_elements,
           size_t element_size,
           int (*compare)(const void*, const void*));
#ifdef __cplusplus
}
#endif

#endif
