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

void tty_write_string_kernel(const char *s);

static spinlock log_buffer_lock;
static char log_temp_buffer[10000];

static void __flush_print()
{
	#ifdef __is_onyx_kernel
	kernlog_print(log_temp_buffer);
	#endif
	memset(buffer, 0, sizeof(log_temp_buffer));
}

void __flush_print_screen()
{
#ifdef __is_onyx_kernel
	tty_write_string_kernel(buffer);
#endif
	memset(buffer, 0, sizeof(buffer));
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
int vprintf(const char *__restrict__ format, va_list va)
{
	scoped_lock g{log_buffer_lock};

	int i = vsnprintf(log_temp_buffer, 10000, format, va);
	if(i < 0)
		return -1;
	__flush_print();

	return i;
}

extern "C"
int printf(const char *__restrict__ format, ...)
{
	va_list va;
	va_start(va, format);
	int i = vprintf(format, va);

	va_end(va);
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

void bust_printk_lock(void)
{
	buffer_lock.counter = 0;
}
