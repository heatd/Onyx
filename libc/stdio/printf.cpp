/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#ifdef __is_onyx_kernel
#include <onyx/log.h>
#include <onyx/mutex.h>
#include <onyx/spinlock.h>
#include <onyx/scoped_lock.h>
#endif

static mutex buffer_lock;
static char buffer[10000];
int bufferPos = 0;
void print(const char *data, size_t data_length)
{
	size_t i;
	for ( i = 0; i < data_length; i++)
	{
		buffer[bufferPos] = data[i];
		bufferPos++;
	}
}

extern "C"
void tty_write_string_kernel(const char *s);

static void __flush_print()
{
	#ifdef __is_onyx_kernel
	kernlog_print(buffer);
	#endif
	memset(buffer, 0, sizeof(buffer));
	bufferPos = 0;
}

void __flush_print_screen()
{
#ifdef __is_onyx_kernel
	tty_write_string_kernel(buffer);
#endif
	memset(buffer, 0, sizeof(buffer));
	bufferPos = 0;
}

bool is_init = false;
void libc_late_init()
{
	is_init = true;
}
#ifdef __is_onyx_kernel
extern int panicing;

int putchar(int c)
{
	char buf[2];
	buf[0] = (char) c;
	buf[1] = 0;

	kernlog_print(buf);
	return c;
}
#endif

extern "C"
int printf(const char *__restrict__ format, ...)
{
	scoped_mutex<false> g{buffer_lock};
	va_list parameters;
	va_start(parameters, format);
	int i = vsnprintf(buffer, 10000, format, parameters);
	if(i < 0)
		return -1;
	__flush_print();
	va_end(parameters);

	return i;
}

extern "C"
int printk(const char *__restrict__ format, ...)
{
	scoped_mutex<false> g{buffer_lock};
	va_list parameters;
	va_start(parameters, format);
	int i = vsnprintf(buffer, 10000, format, parameters);
	if(i < 0)
		return -1;
	
	__flush_print_screen();
	va_end(parameters);

	return 0;
}
