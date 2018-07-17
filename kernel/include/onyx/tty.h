/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_TTY_H
#define _KERNEL_TTY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <termios.h>

#include <onyx/mutex.h>
#include <onyx/condvar.h>

#ifdef __cplusplus
extern "C" {
#endif

struct tty
{
	struct termios term_io;
	ssize_t (*read)(void *buffer, size_t size, struct tty *tty);
	ssize_t (*write)(void *buffer, size_t size, struct tty *tty);
	unsigned int (*ioctl)(int request, void *argp, struct tty *tty);
	void *priv;
	uintptr_t tty_num;
	struct mutex lock;
	bool line_ready;
	struct cond read_cond;
	struct mutex read_mtx;
	struct tty *next;
	char keyboard_buffer[2048];
	unsigned int keyboard_pos;
};

void tty_putchar(char c);
void tty_write(const char *data, size_t size, struct tty *tty);
void tty_write_string(const char *data, struct tty *tty);
void tty_write_kernel(const char *data, size_t size);
void tty_write_string_kernel(const char *data);
void tty_set_color(int color);
int tty_create_pty_and_switch(void*);
void tty_swap_framebuffers();
void tty_init(void *priv, void (*ctor)(struct tty *tty));
void tty_scroll();
void tty_put_entry_at(char c, uint32_t color, size_t column, size_t row);
char *tty_wait_for_line();
void tty_recieved_character(struct tty *tty, char c);
void tty_create_dev();

#ifdef __cplusplus
}
#endif

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#endif
