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
#include <kernel/tty.h>
#endif
#include <ctype.h>
static char printf_buffer[4096] = {0};
static size_t printf_buffer_pos = 0;
static void print(const char *data, size_t data_length)
{
	memcpy(&printf_buffer[printf_buffer_pos], data, data_length);
	printf_buffer_pos += data_length;
}
int tonum(int c);
int isnum(int c);
void itoa(uint64_t i, unsigned int base, char *buf, _Bool is_upper);
int vprintf(const char *__restrict__ format, va_list parameters)
{
	int written = 0;
	size_t amount;
	bool rejected_bad_specifier = false;
	bool pad_zeroes = false;
	unsigned int padding = 0;
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
		if(*format == '0')
		{
			pad_zeroes = 1;
			format++;
		}
		if(isnum(*format))
		{
			padding = tonum(*format);
			format++;
		}
		if(*format == '.')
		{
			padding = tonum(*++format);
			format++;
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
			char printf_buffer[30] = { 0 };
			itoa(i, 16, printf_buffer, true);
			print(printf_buffer, strlen(printf_buffer));
			if(strlen(printf_buffer) < padding)
			{
				if(pad_zeroes)
				{
					char zeroes[padding - strlen(printf_buffer)];
					memset(&zeroes, 0, padding - strlen(printf_buffer));
					printf(zeroes, padding - strlen(printf_buffer));
				}
			}
			memset(printf_buffer, 0, sizeof(printf_buffer));
			format++;
		} else if (*format == 'x') {
			uint64_t i = va_arg(parameters, uint64_t);
			char printf_buffer[30] = { 0 };
			itoa(i, 16, printf_buffer, false);
			print(printf_buffer, strlen(printf_buffer));
			if(strlen(printf_buffer) < padding)
			{
				if(pad_zeroes)
				{
					char zeroes[padding - strlen(printf_buffer)];
					memset(&zeroes, 0, padding - strlen(printf_buffer));
					printf(zeroes, padding - strlen(printf_buffer));
				}
			}
			memset(printf_buffer, 0, sizeof(printf_buffer));
			format++;
		} else if (*format == 'i') {
			format++;
			char string[60];
			itoa(va_arg(parameters, int), 10, string, false);
			print(string, strlen(string));
			if(strlen(string) < padding)
			{
				if(pad_zeroes)
				{
					char zeroes[padding - strlen(string)];
					memset(&zeroes, 0, padding - strlen(string));
					printf(zeroes, padding - strlen(string));
				}
			}
		} else if (*format == 'd') {
			format++;
			char string[60];
			itoa(va_arg(parameters, int), 10, string, false);
			print(string, strlen(string));
			if(strlen(string) < padding)
			{
				if(pad_zeroes)
				{
					char zeroes[padding - strlen(string)];
					memset(&zeroes, 0, padding - strlen(string));
					printf(zeroes, padding - strlen(string));
				}
			}
		} else if (*format == 'p') {
			format++;
			void *ptr = va_arg(parameters, void *);
			if (!ptr)
				print("(nil)", strlen("(nil)"));
			else {
				uintptr_t i = (uintptr_t) ptr;
				char printf_buffer[60] = { 0 };
				itoa(i, 16, printf_buffer, true);
				print("0x", strlen("0x"));
				print(printf_buffer, 60);
				if(strlen(printf_buffer) < padding)
			{
				if(pad_zeroes)
				{
					char zeroes[padding - strlen(printf_buffer)];
					memset(&zeroes, 0, padding - strlen(printf_buffer));
					printf(zeroes, padding - strlen(printf_buffer));
				}
			}
			}
		} else if(*format == 'u')
		{
			format++;
			unsigned int i = va_arg(parameters, unsigned int);
			char string[60];
			itoa(i, 10, string, false);
			print(string, strlen(string));
			if(strlen(string) < padding)
			{
				if(pad_zeroes)
				{
					char zeroes[padding - strlen(string)];
					memset(&zeroes, 0, padding - strlen(string));
					printf(zeroes, padding - strlen(string));
				}
			}
		}
		else
		{
			goto incomprehensible_conversion;
		}
	}
#ifndef __is_onyx_kernel
	fwrite(printf_buffer, printf_buffer_pos, 1, stdout);
	printf_buffer_pos = 0;
	memset(printf_buffer, 0, 4096);
#else
	tty_write(printf_buffer, printf_buffer_pos);
	printf_buffer_pos = 0;
	memset(printf_buffer, 0, 4096);
#endif
	return written;
}
