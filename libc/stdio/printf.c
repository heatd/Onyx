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
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#ifdef __is_spartix_kernel
#include <kernel/log.h>
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
char buffer[500];
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
void flushPrint()
{
	#ifdef __is_spartix_kernel
	kernlog_print(buffer);
	#endif
	memset(buffer, 0 ,500);
	bufferPos = 0;
}
void flushPrint_screen()
{
	#ifdef __is_spartix_kernel
	tty_write_string(buffer);
	#endif
	memset(buffer, 0 ,500);
	bufferPos = 0;
}
bool is_init = false;
void libc_late_init()
{
	is_init = true;
}
#ifdef __is_spartix_kernel
//static spinlock_t spl;
extern int panicing;
#endif
int printf(const char *__restrict__ format, ...)
{
#ifdef __is_spartix_kernel
	//if(panicing != 1) acquire_spinlock(&spl);
#endif
#ifdef __is_spartix_kernel
	va_list parameters;
	va_start(parameters, format);

	int written = 0;
	size_t amount;
	bool rejected_bad_specifier = false;

	while (*format != '\0') {
		if (*format != '%') {
		      print_c:
			amount = 1;
			while (format[amount] && format[amount] != '%')
				amount++;
			print(format, amount);
			format += amount;
			written += amount;
			continue;
		}

		const char *format_begun_at = format;

		if (*(++format) == '%')
			goto print_c;

		if (rejected_bad_specifier) {
		      incomprehensible_conversion:
			rejected_bad_specifier = true;
			format = format_begun_at;
			goto print_c;
		}

		if (*format == 'c') {
			format++;
			char c =
			    (char) va_arg(parameters,
					  int /* char promotes to int */ );
			print(&c, sizeof(c));
		} else if (*format == 's') {
			format++;
			const char *s = va_arg(parameters, const char *);
			print(s, strlen(s));
		} else if (*format == 'X') {
			uint64_t i = va_arg(parameters, uint64_t);
			char buffer[30] = { 0 };
			itoa(i, 16, buffer, true);
			print(buffer, strlen(buffer));
			memset(buffer, 0, sizeof(buffer));
			format++;
		} else if (*format == 'x') {
			uint64_t i = va_arg(parameters, uint64_t);
			char buffer[30] = { 0 };
			itoa(i, 16, buffer, false);
			print(buffer, strlen(buffer));
			memset(buffer, 0, sizeof(buffer));
			format++;
		} else if (*format == 'i') {
			format++;
			char string[60];
			itoa(va_arg(parameters, int), 10, string, false);
			print(string, strlen(string));
		} else if (*format == 'd') {
			format++;
			char string[60];
			itoa(va_arg(parameters, int), 10, string, false);
			print(string, strlen(string));
		} else if(*format == 'u')
		{
			format++;
			char string[60];
			itoa(va_arg(parameters, unsigned int), 10, string, false);
			print(string, strlen(string));	
		} else if(*format == 'p') {
			format++;
			void *ptr = va_arg(parameters, void *);
			if (!ptr)
				print("(nil)", strlen("(nil)"));
			else {
				uintptr_t i = (uintptr_t) ptr;
				char buffer[60] = { 0 };
				itoa(i, 16, buffer, false);
				print("0x", strlen("0x"));
				print(buffer, strlen(buffer));
			}
		} else {
			goto incomprehensible_conversion;
		}
	}
	flushPrint();
	va_end(parameters);

#ifdef __is_spartix_kernel
	//release_spinlock(&spl);
#endif
	return written;
#else
	va_list params;
	va_start(params, format);
	int ret = vprintf(format, params);
	va_end(params);
	return ret;
#endif
}
int printk(const char *__restrict__ format, ...)
{
#ifdef __is_spartix_kernel
	//if(panicing != 1) acquire_spinlock(&spl);
#endif
#ifdef __is_spartix_kernel
	va_list parameters;
	va_start(parameters, format);

	int written = 0;
	size_t amount;
	bool rejected_bad_specifier = false;

	while (*format != '\0') {
		if (*format != '%') {
		      print_c:
			amount = 1;
			while (format[amount] && format[amount] != '%')
				amount++;
			print(format, amount);
			format += amount;
			written += amount;
			continue;
		}

		const char *format_begun_at = format;

		if (*(++format) == '%')
			goto print_c;

		if (rejected_bad_specifier) {
		      incomprehensible_conversion:
			rejected_bad_specifier = true;
			format = format_begun_at;
			goto print_c;
		}

		if (*format == 'c') {
			format++;
			char c =
			    (char) va_arg(parameters,
					  int /* char promotes to int */ );
			print(&c, sizeof(c));
		} else if (*format == 's') {
			format++;
			const char *s = va_arg(parameters, const char *);
			print(s, strlen(s));
		} else if (*format == 'X') {
			uint64_t i = va_arg(parameters, uint64_t);
			char buffer[30] = { 0 };
			itoa(i, 16, buffer, true);
			print(buffer, strlen(buffer));
			memset(buffer, 0, sizeof(buffer));
			format++;
		} else if (*format == 'x') {
			uint64_t i = va_arg(parameters, uint64_t);
			char buffer[30] = { 0 };
			itoa(i, 16, buffer, false);
			print(buffer, strlen(buffer));
			memset(buffer, 0, sizeof(buffer));
			format++;
		} else if (*format == 'i') {
			format++;
			char string[60];
			itoa(va_arg(parameters, int), 10, string, false);
			print(string, strlen(string));
		} else if (*format == 'd') {
			format++;
			char string[60];
			itoa(va_arg(parameters, int), 10, string, false);
			print(string, strlen(string));
		} else if(*format == 'u')
		{
			format++;
			char string[60];
			itoa(va_arg(parameters, unsigned int), 10, string, false);
			print(string, strlen(string));	
		} else if(*format == 'p') {
			format++;
			void *ptr = va_arg(parameters, void *);
			if (!ptr)
				print("(nil)", strlen("(nil)"));
			else {
				uintptr_t i = (uintptr_t) ptr;
				char buffer[60] = { 0 };
				itoa(i, 16, buffer, false);
				print("0x", strlen("0x"));
				print(buffer, strlen(buffer));
			}
		} else {
			goto incomprehensible_conversion;
		}
	}
	flushPrint_screen();
	va_end(parameters);

#ifdef __is_spartix_kernel
	//release_spinlock(&spl);
#endif
	return written;
#else
	va_list params;
	va_start(params, format);
	int ret = vprintf(format, params);
	va_end(params);
	return ret;
#endif
}
