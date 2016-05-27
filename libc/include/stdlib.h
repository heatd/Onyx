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
typedef int ssize_t;
int atexit(void (*)(void));
int atoi(const char*);
char* getenv(const char*);
__attribute__((__noreturn__))
void abort(void);
void free(void*);
void* malloc(size_t size);
#ifdef __cplusplus
}
#endif

#endif
