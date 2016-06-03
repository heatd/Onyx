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
int currentPty = 0;
void* fbs[5] ={(void*)0xDEADDEAD/*Vid mem*/,nullptr};
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
	SoftwareFramebuffer::DrawChar('\0', last_x, last_y, 0, 0, fbs[currentPty]);
	int y = row * 16;
	int x = column * 9;
	last_x = x + 9;
	last_y = y;
	SoftwareFramebuffer::DrawChar(c, x, y, color, 0, fbs[currentPty]);
	SoftwareFramebuffer::DrawChar('\0', x + 9, y, 0, 0xC0C0C0, fbs[currentPty]);
}
void TTY::PutChar(char c)
{
	if (c == '\n') {
		newline:
		terminal_column = 0;
		terminal_row++;
		if(terminal_row >= max_row)
		{
			SoftwareFramebuffer::DrawChar('\0', last_x, last_y, 0, 0, fbs[currentPty]);
			TTY::Scroll();
		}
		SoftwareFramebuffer::DrawChar('\0', last_x, last_y, 0, 0, fbs[currentPty]);
		SoftwareFramebuffer::DrawChar('\0', terminal_column * 9, terminal_row * 16, 0,
			  0xC0C0C0, fbs[currentPty]);
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
static spinlock_t spl;
void TTY::Write(const char *data, size_t size)
{
	(void)spl;
	uint64_t rflags = __builtin_ia32_readeflags_u64();
	asm volatile("cli");
	acquire(&spl);
	for (size_t i = 0; i < size; i++)
		PutChar(data[i]);
	if(currentPty != 0)
		SwapFramebuffers();
	release(&spl);
	if(rflags & 0x200)
		asm volatile("sti");
}
void TTY::SwapFramebuffers()
{
	memcpy(SoftwareFramebuffer::GetFBAddress(), fbs[currentPty], 0x400000);
}
void TTY::WriteString(const char *data)
{
	Write(data, strlen(data));
}
void TTY::Scroll()
{
	SoftwareFramebuffer::Scroll(fbs[currentPty]);
	terminal_row--;
	terminal_column = 0;
	SwapFramebuffers();
}
int TTY::CreatePTYAndSwitch(void* address)
{
	currentPty++;
	/* Save the fb address */
	fbs[currentPty] = address;
	memset(SoftwareFramebuffer::GetFBAddress(), 0, 0x400000);
	terminal_row = 1;
	terminal_column = 0;
	SoftwareFramebuffer::DrawChar('\0', terminal_column * 9, terminal_row * 16, 0,
		  0xC0C0C0, fbs[currentPty]);
	last_x = terminal_column * 9;
	last_y = terminal_row * 16;
	SwapFramebuffers();
	return 0;
}
