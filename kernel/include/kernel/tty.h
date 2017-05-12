/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_TTY_H
#define _KERNEL_TTY_H

#include <stddef.h>
#include <stdint.h>

void tty_putchar(char c);
void tty_write(const char *data, size_t size);
void tty_write_string(const char *data);
void tty_set_color(int color);
int tty_create_pty_and_switch(void*);
void tty_swap_framebuffers();
void tty_init(void);
void tty_scroll();
void tty_put_entry_at(char c, uint32_t color, size_t column, size_t row);
char *tty_wait_for_line();
void tty_recieved_character(char c);
void tty_create_dev();
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define TTY_DEFAULT_RED 0xFF0000
#define TTY_DEFAULT_GREEN 0x00FF00
#define TTY_DEFAULT_BLUE 0xFF
#define TTY_DEFAULT_YELLOW 0xFFFF00
#define TTY_DEFAULT_MAGENTA 0xFF00FF
#define TTY_DEFAULT_CYAN 0x00FFFF
#define TTY_RESET_COLOR 0xC0C0C0
#endif