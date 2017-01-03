/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
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
#undef va_list /* ACPICA defines va_list, which messes up the kernel's compilation */
#include <stdarg.h>
#ifdef __is_spartix_kernel
#include <kernel/spinlock.h>
#endif
#ifdef __cplusplus
__START_C_HEADER
#endif

#ifndef __need_FILE
#define __need_FILE 1
#endif
#if defined(__need_FILE) && !defined(__FILE_defined)
struct _IO_FILE;
typedef struct _IO_FILE FILE;
extern FILE* stderr;
#define stderr stderr
extern FILE* stdout;
#define stdout stdout
extern FILE* stdin;
#define stdin stdin

#ifndef __size_t_defined
#define __need_size_t 1
#include <stddef.h>
#endif

#undef SEEK_SET
#define SEEK_SET 1
#undef SEEK_CUR
#define SEEK_CUR 2
#undef SEEK_END
#define SEEK_END 3

int fprintf(FILE*, const char*, ...);
int fclose(FILE*);
FILE* fopen(const char*, const char*);
size_t fread(void*, size_t, size_t, FILE*);
int fseek(FILE*, long, int);
long ftell(FILE*);
size_t fwrite(const void*, size_t, size_t, FILE*);
void setbuf(FILE*, char*);
void rewind(FILE *stream);
char *gets(char *buf);
char *fgets(char *buf, int size, FILE *stream);
#endif /* __need_FILE */

int vsprintf(char *restrict s, const char *__restrict__ format, va_list parameters);
int vprintf(const char *__restrict__ format, va_list parameters);
int printf(const char *s, ...);
int putchar(int);
int puts(const char*);

void perror(const char *errmsg);

char *tmpnam(char *b);

#ifdef __cplusplus
__END_C_HEADER
#endif

#endif
