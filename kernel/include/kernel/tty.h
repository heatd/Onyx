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
#pragma once
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
