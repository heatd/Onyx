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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <ctype.h>
int vsprintf(char *restrict s, const char *__restrict__ format, va_list parameters)
{
	int written = 0;
	size_t amount;
	bool rejected_bad_specifier = false;
	bool pad_zeroes = false;
	unsigned int padding = 0;
	char *restrict streamstr = s;
	while (*format != '\0') {
		if (*format != '%') {
		      print_c:
			amount = 1;
			while (format[amount] && format[amount] != '%')
				amount++;
			for(size_t i = 0; i < amount; i++)
				*streamstr++ = format[amount];
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
			*streamstr++ = c;
		} else if (*format == 's') {
			format++;
			const char *str = va_arg(parameters, const char *);
			streamstr = stpcpy(streamstr, str);
		} else if (*format == 'X') {
			uint64_t i = va_arg(parameters, uint64_t);
			char buffer[30] = { 0 };
			itoa(i, 16, buffer, true);
			streamstr = stpcpy(streamstr, buffer);
			if(strlen(buffer) < padding)
			{
				if(pad_zeroes)
				{
					char zeroes[padding - strlen(buffer)];
					memset(&zeroes, '0', padding - strlen(buffer));
					memcpy(streamstr, zeroes, padding - strlen(buffer));
					streamstr += padding - strlen(buffer);
				}
			}
			memset(buffer, 0, sizeof(buffer));
			format++;
		} else if (*format == 'x') {
			uint64_t i = va_arg(parameters, uint64_t);
			char buffer[30] = { 0 };
			itoa(i, 16, buffer, false);
			streamstr = stpcpy(streamstr, buffer);
			if(strlen(buffer) < padding)
			{
				if(pad_zeroes)
				{
					char zeroes[padding - strlen(buffer)];
					memset(&zeroes, '0', padding - strlen(buffer));
					memcpy(streamstr, zeroes, padding - strlen(buffer));
					streamstr += padding - strlen(buffer);
				}
			}
			memset(buffer, 0, sizeof(buffer));
			format++;
		} else if (*format == 'i') {
			format++;
			char string[60];
			itoa(va_arg(parameters, int), 10, string, false);
			streamstr = stpcpy(streamstr, string);
			if(strlen(string) < padding)
			{
				if(pad_zeroes)
				{
					char zeroes[padding - strlen(string)];
					memset(&zeroes, '0', padding - strlen(string));
					memcpy(streamstr, zeroes, padding - strlen(string));
					streamstr += padding - strlen(string);
				}
			}
		} else if (*format == 'd') {
			format++;
			char string[60];
			itoa(va_arg(parameters, int), 10, string, false);
			streamstr = stpcpy(streamstr, string);
			if(strlen(string) < padding)
			{
				if(pad_zeroes)
				{
					char zeroes[padding - strlen(string)];
					memset(&zeroes, '0', padding - strlen(string));
					memcpy(streamstr, zeroes, padding - strlen(string));
					streamstr += padding - strlen(string);
				}
			}
		} else if (*format == 'p') {
			format++;
			void *ptr = va_arg(parameters, void *);
			if (!ptr)
				streamstr = stpcpy(streamstr, "(nil)");
			else {
				uintptr_t i = (uintptr_t) ptr;
				char buffer[60] = { 0 };
				itoa(i, 16, buffer, true);
				streamstr = stpcpy(streamstr, "0x");
				streamstr = stpcpy(streamstr, buffer);
				if(strlen(buffer) < padding)
			{
				if(pad_zeroes)
				{
					char zeroes[padding - strlen(buffer)];
					memset(&zeroes, '0', padding - strlen(buffer));
					memcpy(streamstr, zeroes, padding - strlen(buffer));
					streamstr += padding - strlen(buffer);
				}
			}
			}
		} else if(*format == 'u')
		{
			format++;
			unsigned int i = va_arg(parameters, unsigned int);
			char string[60];
			itoa(i, 10, string, false);
			streamstr = stpcpy(streamstr, string);
			if(strlen(string) < padding)
			{
				if(pad_zeroes)
				{
					char zeroes[padding - strlen(string)];
					memset(&zeroes, '0', padding - strlen(string));
					memcpy(streamstr, zeroes, padding - strlen(string));
					streamstr += padding - strlen(string);
				}
			}
		}
		else
		{
			goto incomprehensible_conversion;
		}
	}
	return written;
}