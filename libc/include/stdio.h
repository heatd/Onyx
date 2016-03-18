/* Copyright 2016 Pedro Falcato

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _STDIO_H
#define _STDIO_H 1

#include <sys/cdefs.h>
#include <string.h>
#include <stdarg.h>
#ifdef __is_spartix_kernel
#include <kernel/spinlock.h>
#endif
#ifdef __cplusplus
extern "C" {
#endif
#define SEEK_SET 0
typedef struct { int unused; } FILE;
extern FILE* stderr;
#define stderr stderr
int fprintf(FILE*, const char*, ...);
int fclose(FILE*);
FILE* fopen(const char*, const char*);
size_t fread(void*, size_t, size_t, FILE*);
int fseek(FILE*, long, int);
long ftell(FILE*);
size_t fwrite(const void*, size_t, size_t, FILE*);
void setbuf(FILE*, char*);
int vfprintf(FILE*, const char*, va_list);
int printf(const char* __restrict, ...);
int putchar(int);
int puts(const char*);
#ifdef __cplusplus
}
#endif

#endif
