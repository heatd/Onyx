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
#ifndef _STDIO_H
#define _STDIO_H 1

#include <sys/cdefs.h>
#include <string.h>
#undef va_list
#include <stdarg.h>
#include <unistd.h>
#ifdef __is_spartix_kernel
#include <kernel/spinlock.h>
#endif
#ifdef __cplusplus
extern "C" {
#endif

struct _IO_FILE;
typedef struct _IO_FILE FILE;

extern FILE* stderr;
#define stderr stderr
extern FILE* stdout;
#define stdout stdout
extern FILE* stdin;
#define stdin stdin

int fprintf(FILE*, const char*, ...);
int fclose(FILE*);
FILE* fopen(const char*, const char*);
size_t fread(void*, size_t, size_t, FILE*);
int fseek(FILE*, long, int);
long ftell(FILE*);
size_t fwrite(const void*, size_t, size_t, FILE*);
int vsprintf(char *restrict s, const char *__restrict__ format, va_list parameters);

#undef setbuf
void setbuf(FILE*, char*);

int printf(const char* __restrict, ...);
int vprintf(const char *__restrict__ format, va_list parameters);

#undef putchar
int putchar(int);
int puts(const char*);

#ifdef __cplusplus
}
#endif

#endif
