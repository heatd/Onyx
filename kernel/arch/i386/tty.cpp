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
size_t terminal_row;
size_t terminal_column;
uint32_t last_x;
uint32_t last_y;
int terminal_color;
void TTY::Init(void)
{
	terminal_row = 1;
	terminal_column = 0;
	terminal_color = 0xC0C0C0;
}

void TTY::SetColor(int color)
{
	terminal_color = color;
}

void terminal_putentryat(char c, uint8_t color, size_t column, size_t row)
{
	Vesa::DrawChar('\0',last_x,last_y,0,0);
	int y = row * 16;
	int x = column * 9;
	last_x = x + 9;
	last_y = y;
	Vesa::DrawChar(c,x,y,terminal_color,0);
	Vesa::DrawChar('\0',x + 9,y,0,0xC0C0C0);
}
void TTY::PutChar(char c)
{
	if(c == '\n'){
		terminal_column = 0;
		terminal_row++;
		Vesa::DrawChar('\0',last_x,last_y,0,0);
		Vesa::DrawChar('\0',terminal_column *9,terminal_row * 16,0,0xC0C0C0);
		last_x = terminal_column * 9;
		last_y = terminal_row * 16;
		return;
	}
	terminal_putentryat(c, terminal_color, terminal_column, terminal_row);
	terminal_column++;
}
void TTY::ClearCursor(uint32_t terminal_column, uint32_t terminal_row)
{
	uint32_t x = terminal_column * 16;
	uint32_t y = terminal_row * 9;
	for(int i = 0; i < 5;i++)
	{
		for(int j = 0;j < 15; j++)
		{
			Vesa::PutPixel(x + j, y + i,0);
		}
	}
}
void TTY::UpdateCursor()
{

	uint32_t x = terminal_column + 1 * 16 - 14;
	uint32_t y = terminal_row * 9;
	/*last_x = x;
	last_y = y;
	int k = 0;
	for(int i = 0; i < 5;i++)
	{
		for(int j = 0;j < 15; j++)
		{
			Vesa::PutPixel(x + j, y + i,0xC0C0C0);
		}
	}*/
	Vesa::DrawChar('\0',x,y,0x0,0xC0C0C0);
}
void TTY::Write(const char* data, size_t size)
{
	for ( size_t i = 0; i < size; i++ )
		PutChar(data[i]);
}

void TTY::WriteString(const char* data)
{
	Write(data, strlen(data));
}
