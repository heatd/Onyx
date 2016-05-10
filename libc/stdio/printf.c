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
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdint-gcc.h>
#include <stdlib.h>
char tbuf[32];
char bchars[] =
    { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
'E', 'F' };
char lchars[] =
    { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
'e', 'f' };
void itoa(unsigned int i, unsigned int base, char *buf, _Bool is_upper)
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

static void print(const char *data, size_t data_length)
{
	size_t i;
	for ( i = 0; i < data_length; i++)
		putchar((int) ((const unsigned char *) data)[i]);
}

#ifdef __is_spartix_kernel
static spinlock_t spl;
#endif
int printf(const char *__restrict__ format, ...)
{
#ifdef __is_spartix_kernel
	acquire(&spl);
#endif
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
			unsigned int i = va_arg(parameters, uint32_t);
			char buffer[30] = { 0 };
			itoa(i, 16, buffer, true);
			print(buffer, strlen(buffer));
			memset(buffer, 0, sizeof(buffer));
			format++;
		} else if (*format == 'x') {
			unsigned int i = va_arg(parameters, uint32_t);
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
		} else if (*format == 'p') {
			format++;
			void *ptr = va_arg(parameters, void *);
			if (!ptr)
				print("(nil)", strlen("(nil)"));
			else {
				unsigned int i = (unsigned int) ptr;
				char buffer[30] = { 0 };
				itoa(i, 16, buffer, true);
				print("0x", strlen("0x"));
				print(buffer, 30);
			}
		} else if (*format == 'f') {
			format++;
			char string[60];
			double dbl = va_arg(parameters, double);
			itoa((int)dbl, 10, string, false);
			print(string, strlen(string));
			memset(&string, 0, 60);
			print(".",1);
			if(dbl < 0)
				dbl = -dbl;
			dbl = (dbl - (int)dbl) * 1000000;
			itoa((int)dbl, 10, string, false);
			print(string, strlen(string));
		} else {
			goto incomprehensible_conversion;
		}
	}

	va_end(parameters);

#ifdef __is_spartix_kernel
	release(&spl);
#endif
	return written;
}
