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
#include <drivers/softwarefb.h>
#include <stdio.h>

void TTY::Init(void)
{
	terminal_row = 1;
	terminal_column = 0;
	terminal_color = 0xC0C0C0;
	VideoMode *vid = SoftwareFramebuffer::GetVideomode();
	if( vid->width == 0 ) {
		max_row = max_row_fallback;
		max_column = max_column_fallback;
	} else {
		max_row = vid->height / 16;
		max_column = vid->width / 9;
	}
}

void TTY::SetColor(int color)
{
	terminal_color = color;
}

void TTY::PutEntryAt(char c, uint32_t color, size_t column, size_t row)
{
	SoftwareFramebuffer::DrawChar('\0', last_x, last_y, 0, 0);
	int y = row * 16;
	int x = column * 9;
	last_x = x + 9;
	last_y = y;
	SoftwareFramebuffer::DrawChar(c, x, y, color, 0);
	SoftwareFramebuffer::DrawChar('\0', x + 9, y, 0, 0xC0C0C0);
}
void TTY::PutChar(char c)
{
	if (c == '\n') {
		newline:
		terminal_column = 0;
		terminal_row++;
		SoftwareFramebuffer::DrawChar('\0', last_x, last_y, 0, 0);
		SoftwareFramebuffer::DrawChar('\0', terminal_column * 9, terminal_row * 16, 0,
			  0xC0C0C0);
		last_x = terminal_column * 9;
		last_y = terminal_row * 16;
		return;
	}
	if( terminal_column == max_column ) {
		/* If we reach the line limit, fake a newline */
		goto newline;
	}
	PutEntryAt(c, terminal_color, terminal_column,
			    terminal_row);
	terminal_column++;
}
void TTY::Write(const char *data, size_t size)
{
	for (size_t i = 0; i < size; i++)
		PutChar(data[i]);
}

void TTY::WriteString(const char *data)
{
	Write(data, strlen(data));
}