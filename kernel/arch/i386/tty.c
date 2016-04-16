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
/**************************************************************************
 *
 *
 * File: tty.c
 *
 * Description: Contains the text terminal initialization and manipulation code
 *
 * Date: 30/1/2016
 *
 *
 **************************************************************************/
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <kernel/portio.h>
#include <kernel/vga.h>
#include <kernel/tty.h>
#include <drivers/vesa.h>
#include <stdio.h>
#include <kernel/spinlock.h>
#include <drivers/serial.h>
size_t terminal_row;
size_t terminal_column;
uint32_t last_x;
uint32_t last_y;
int terminal_color;
static unsigned int max_row;
static const unsigned int max_row_fallback = 1024/16;
static unsigned int max_column;
static const unsigned int max_column_fallback = 768/9;
void tty_init(void)
{
	terminal_row = 1;
	terminal_column = 0;
	terminal_color = 0xC0C0C0;
	vid_mode_t *vid = vesa_get_videomode();
	if( vid->width == 0 ) {
		max_row = max_row_fallback;
		max_column = max_column_fallback;
	} else {
		max_row = vid->height / 16;
		max_column = vid->width / 9;
	}
}

void tty_set_color(int color)
{
	terminal_color = color;
}

void terminal_putentryat(char c, uint32_t color, size_t column, size_t row)
{
	draw_char('\0', last_x, last_y, 0, 0);
	int y = row * 16;
	int x = column * 9;
	last_x = x + 9;
	last_y = y;
	draw_char(c, x, y, color, 0);
	draw_char('\0', x + 9, y, 0, 0xC0C0C0);
}
void tty_scroll()
{
	if ( terminal_row == max_row ) {
		serial_write_string("tty0: scrolling\n");
		vesa_scroll();
	}
	else {
		terminal_row++;
	}
	if( terminal_row > max_row ) {
		serial_write_string("tty0: terminal_row > max_row\n");
	}
}
void tty_putchar(char c)
{
	if (c == '\n') {
		newline:
		terminal_column = 0;
		tty_scroll();
		draw_char('\0', last_x, last_y, 0, 0);
		draw_char('\0', terminal_column * 9, terminal_row * 16, 0,
			  0xC0C0C0);
		last_x = terminal_column * 9;
		last_y = terminal_row * 16;
		return;
	}
	if( terminal_column == max_column ) {
		/* If we reach the line limit, fake a newline */
		goto newline;
	}
	terminal_putentryat(c, terminal_color, terminal_column,
			    terminal_row);
	terminal_column++;
}

static spinlock_t spl;
void tty_write(const char *data, size_t size)
{
	acquire(&spl);
	for (size_t i = 0; i < size; i++)
		tty_putchar(data[i]);
	release(&spl);
}

void tty_write_string(const char *data)
{
	tty_write(data, strlen(data));
}
