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
#ifndef _STRING_LIBC_H
#define _STRING_LIBC_H 1

#include <sys/cdefs.h>

#include <stddef.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

int memcmp(const void*, const void*, size_t);
void *memcpy(void* __restrict__, const void* __restrict__, size_t);
void *memmove(void*, const void*, size_t);
void *memset(void*, int, size_t);
size_t strlen(const char*);
char *strcat(char *dest, const char *src);
char *strcpy(char *dest, const char *src);
int strcmp(char *s, char *t);
char *strstr(char *str, char *substr);
char* strtok(char* s, char* delm);
void *memchr(const void *str, int c, size_t n);
wchar_t *wmemcpy(wchar_t *restrict ws1, const wchar_t *restrict ws2, size_t n);
char *stpcpy(char *restrict s1, const char *restrict s2);
char *strerror(int errnum);
#ifdef __cplusplus
}
#endif

#endif
