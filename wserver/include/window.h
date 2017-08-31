/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _WINDOW_H
#define _WINDOW_H

struct window
{
	void *window_backbuffer;
	size_t backbuffer_size;
	unsigned int client_width;
	unsigned int client_height;
	unsigned int x;
	unsigned int y;
	unsigned int window_width;
	unsigned int window_height;

	struct window *next;
};

struct window *window_create(unsigned int x, unsigned int y, unsigned int width, unsigned int height);
void draw_windows(void);
void draw_window(struct window *w);

#endif
