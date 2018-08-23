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
#endif
char tbuf[32];
char bchars[] =
    { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
'E', 'F' };
char lchars[] =
    { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
'e', 'f' };
void itoa(uint64_t i, unsigned int base, char *buf, _Bool is_upper)
{
	int pos = 0;
	int opos = 0;
	int top = 0;

	if (i == 0 || base > 16) {
		buf[0] = '0';
		buf[1] = '\0';
		return;
	}
	if (is_upper == false) {
		while (i != 0) {
			tbuf[pos] = lchars[i % base];
			pos++;
			i /= base;
		}
	} else {
		while (i != 0) {
			tbuf[pos] = bchars[i % base];
			pos++;
			i /= base;
		}
	}
	top = pos--;
	for (opos = 0; opos < top; pos--, opos++) {
		buf[opos] = tbuf[pos];
	}
	buf[opos] = 0;
}
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

static void __flush_print()
{
	#ifdef __is_onyx_kernel
	kernlog_print(buffer);
	#endif
	memset(buffer, 0, 10000);
	bufferPos = 0;
}

void __flush_print_screen()
{
	#ifdef __is_onyx_kernel
	tty_write_string_kernel(buffer);
	#endif
	memset(buffer, 0, 10000);
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

	kernlog_print(&buf);
	return c;
}
#endif

int printf(const char *__restrict__ format, ...)
{
	va_list parameters;
	va_start(parameters, format);
	int i = vsnprintf(buffer, 10000, format, parameters);
	if(i < 0)
		return -1;
	__flush_print();
	va_end(parameters);

	return i;
}

int printk(const char *__restrict__ format, ...)
{
	va_list parameters;
	va_start(parameters, format);
	int i = vsnprintf(buffer, 10000, format, parameters);
	if(i < 0)
		return -1;
	__flush_print_screen();
	va_end(parameters);
}
