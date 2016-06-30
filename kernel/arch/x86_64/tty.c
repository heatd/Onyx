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
#include <kernel/spinlock.h>
#include <stdio.h>
unsigned int max_row = 0;
static const unsigned int max_row_fallback = 1024/16;
unsigned int max_column = 0;
static const unsigned int max_column_fallback = 768/9;
size_t terminal_row = 0;
size_t terminal_column = 0;
uint32_t last_x = 0;
uint32_t last_y = 0;
int terminal_color = 0;
int currentPty = 0;
void* fbs[5] ={(void*)0xDEADDEAD/*Vid mem*/,NULL};
void tty_init(void)
{
	terminal_row = 1;
	terminal_column = 0;
	terminal_color = 0xC0C0C0;
	videomode_t *vid = softfb_getvideomode();
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

void tty_put_entry_at(char c, uint32_t color, size_t column, size_t row)
{
	softfb_draw_char('\0', last_x, last_y, 0, 0, fbs[currentPty]);
	int y = row * 16;
	int x = column * 9;
	last_x = x + 9;
	last_y = y;
	softfb_draw_char(c, x, y, color, 0, fbs[currentPty]);
	softfb_draw_char('\0', x + 9, y, 0, 0xC0C0C0, fbs[currentPty]);
}
void tty_putchar(char c)
{
	if (c == '\n') {
		newline:
		terminal_column = 0;
		terminal_row++;
		if(terminal_row >= max_row)
		{
			softfb_draw_char('\0', last_x, last_y, 0, 0, fbs[currentPty]);
			tty_scroll();
		}
		softfb_draw_char('\0', last_x, last_y, 0, 0, fbs[currentPty]);
		softfb_draw_char('\0', terminal_column * 9, terminal_row * 16, 0,
			  0xC0C0C0, fbs[currentPty]);
		last_x = terminal_column * 9;
		last_y = terminal_row * 16;
		return;
	}
	if( terminal_column == max_column ) {
		/* If we reach the line limit, fake a newline */
		goto newline;
	}
	tty_put_entry_at(c, terminal_color, terminal_column,
			    terminal_row);
	terminal_column++;
}
static spinlock_t spl;
void tty_write(const char *data, size_t size)
{
	acquire_spinlock(&spl);
	for (size_t i = 0; i < size; i++)
		tty_putchar(data[i]);
	if(currentPty != 0)
		tty_swap_framebuffers();
	release_spinlock(&spl);
}
void tty_swap_framebuffers()
{
	memcpy(softfb_getfb(), fbs[currentPty], 0x400000);
}
void tty_write_string(const char *data)
{
	tty_write(data, strlen(data));
}
void tty_scroll()
{
	softfb_scroll(fbs[currentPty]);
	terminal_row--;
	terminal_column = 0;
	tty_swap_framebuffers();
}
int tty_create_pty_and_switch(void* address)
{
	currentPty++;
	/* Save the fb address */
	fbs[currentPty] = address;
	memset(softfb_getfb(), 0, 0x400000);
	terminal_row = 1;
	terminal_column = 0;
	softfb_draw_char('\0', terminal_column * 9, terminal_row * 16, 0,
		  0xC0C0C0, fbs[currentPty]);
	last_x = terminal_column * 9;
	last_y = terminal_row * 16;
	tty_swap_framebuffers();
	return 0;
}
