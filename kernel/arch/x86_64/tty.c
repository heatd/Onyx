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
#include <kernel/tty.h>
#include <drivers/softwarefb.h>
#include <kernel/spinlock.h>
#include <stdio.h>

#include <kernel/dev.h>
unsigned int max_row = 0;
static const unsigned int max_row_fallback = 1024/16;
unsigned int max_column = 0;
static const unsigned int max_column_fallback = 768/8;
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
		max_column = vid->width / 8;
	}
}

void tty_set_color(int color)
{
	terminal_color = color;
}

void tty_put_entry_at(char c, uint32_t color, size_t column, size_t row)
{
	softfb_draw_cursor(last_x, last_y, 0, 0, fbs[currentPty]);
	int y = row * 16;
	int x = column * 8;
	last_x = x + 9;
	last_y = y;
	softfb_draw_char(c, x, y, color, 0, fbs[currentPty]);
	softfb_draw_cursor(x + 9, y, 0, 0xC0C0C0, fbs[currentPty]);
}
void tty_putchar(char c)
{
	if(c == '\n')
	{
		newline:
		terminal_column = 0;
		terminal_row++;
		if(terminal_row >= max_row)
		{
			softfb_draw_cursor(last_x, last_y, 0, 0, fbs[currentPty]);
			tty_scroll();
		}
		softfb_draw_cursor(last_x, last_y, 0, 0, fbs[currentPty]);
		softfb_draw_cursor(terminal_column * 8, terminal_row * 16, 0,
			  0xC0C0C0, fbs[currentPty]);
		last_x = terminal_column * 8;
		last_y = terminal_row * 16;
		return;
	}
	if (c == '\t')
	{
		for(int i = 0; i < 8; i++)
		{
			tty_put_entry_at(0x20, terminal_color, terminal_column, terminal_row);
			terminal_column++;
		}
		return;
	}
	if(c == '\b')
	{
		size_t column = 0, row = terminal_row;
		if(terminal_column)
			column = terminal_column-1;
		else
		{
			row--;
			column = max_column;
		}
		softfb_draw_cursor(terminal_column * 8, terminal_row * 16, 0, 0, fbs[currentPty]);
		softfb_draw_cursor(column * 8, row * 16, 0, 0, fbs[currentPty]);
		softfb_draw_cursor(column * 8, row * 16, 0, 0xC0C0C0, fbs[currentPty]);
		int y = row * 16;
		int x = column * 8;
		last_x = x;
		last_y = y;
		terminal_column = column;
		terminal_row = row;
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
	{
		// Parse ANSI terminal escape codes
		if(!memcmp(&data[i], ANSI_COLOR_RED, strlen(ANSI_COLOR_RED)))
		{
			tty_set_color(TTY_DEFAULT_RED);
			i += strlen(ANSI_COLOR_RED);
			if(i >= size) break;
		}
		if(!memcmp(&data[i], ANSI_COLOR_GREEN, strlen(ANSI_COLOR_GREEN)))
		{
			tty_set_color(TTY_DEFAULT_GREEN);
			i += strlen(ANSI_COLOR_GREEN);
			if(i >= size) break;			
		}
		if(!memcmp(&data[i], ANSI_COLOR_YELLOW, strlen(ANSI_COLOR_YELLOW)))
		{
			tty_set_color(TTY_DEFAULT_YELLOW);
			i += strlen(ANSI_COLOR_YELLOW);
			if(i >= size) break;
		}
		if(!memcmp(&data[i], ANSI_COLOR_BLUE, strlen(ANSI_COLOR_BLUE)))
		{
			tty_set_color(TTY_DEFAULT_BLUE);
			i += strlen(ANSI_COLOR_BLUE);
			if(i >= size) break;
		}
		if(!memcmp(&data[i], ANSI_COLOR_MAGENTA, strlen(ANSI_COLOR_MAGENTA)))
		{
			tty_set_color(TTY_DEFAULT_MAGENTA);
			i += strlen(ANSI_COLOR_MAGENTA);
			if(i >= size) break;
		}
		if(!memcmp(&data[i], ANSI_COLOR_CYAN, strlen(ANSI_COLOR_CYAN)))
		{
			tty_set_color(TTY_DEFAULT_CYAN);
			i += strlen(ANSI_COLOR_CYAN);
			if(i >= size) break;
		}
		if(!memcmp(&data[i], ANSI_COLOR_RESET, strlen(ANSI_COLOR_RESET)))
		{
			tty_set_color(TTY_RESET_COLOR);
			i += strlen(ANSI_COLOR_RESET);
			if(i >= size) break;
		}
		tty_putchar(data[i]);
	}
	if(currentPty != 0)
		tty_swap_framebuffers();
	release_spinlock(&spl);
}
#define TTY_PRINT_IF_ECHO(c, l) if(echo) tty_write(c, l)
char keyboard_buffer[2048];
volatile int tty_keyboard_pos = 0;
volatile _Bool got_line_ready = 0;
_Bool echo = true;
void tty_recieved_character(char c)
{
	if(c == '\n')
	{
		got_line_ready = 1;
		TTY_PRINT_IF_ECHO("\n", 1);
		return;
	}
	if(c == '\b')
	{
		if(tty_keyboard_pos <= 0)
		{
			tty_keyboard_pos = 0;
			return;
		}
		TTY_PRINT_IF_ECHO(&c, 1);
		keyboard_buffer[tty_keyboard_pos] = 0;
		tty_keyboard_pos--;
		return;
	}
	keyboard_buffer[tty_keyboard_pos++] = c;
	TTY_PRINT_IF_ECHO(&c, 1);
}
char *tty_wait_for_line()
{
	while(!got_line_ready)
	{
		asm volatile("hlt");
	}
	got_line_ready = 0;
	return keyboard_buffer;
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
size_t ttydevfs_write(size_t offset, size_t sizeofwrite, void* buffer, struct vfsnode* this)
{
	tty_write(buffer, sizeofwrite);
	return sizeofwrite;
}
size_t ttydevfs_read(size_t offset, size_t count, void *buffer, vfsnode_t *this)
{
	char *kb_buf = tty_wait_for_line();
	memcpy(buffer, kb_buf, count);
	tty_keyboard_pos = 0;
	memset(kb_buf, 0, count);
	memmove(kb_buf, &kb_buf[count], count);
	return count;
}
void tty_create_dev()
{
	vfsnode_t *ttydev = creat_vfs(slashdev, "/dev/tty", 0666);
	ttydev->write = ttydevfs_write;
	ttydev->read = ttydevfs_read;
	ttydev->type = VFS_TYPE_CHAR_DEVICE;
}
