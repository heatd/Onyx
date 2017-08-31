/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <pthread.h>

#include <window.h>
#include <display.h>

#include <sys/mman.h>

struct window *window_list = NULL;
pthread_mutex_t window_list_lock = PTHREAD_MUTEX_INITIALIZER;

void window_add(struct window *window)
{
	pthread_mutex_lock(&window_list_lock);

	if(!window_list)
	{
		window_list = window;
	}
	else
	{
		struct window *w = window_list;
		while(w->next) w = w->next;
		w->next = window;
	}

	pthread_mutex_unlock(&window_list_lock);
}

struct window *window_create(unsigned int x, unsigned int y, unsigned int width, unsigned int height)
{
	struct window *w = calloc(1, sizeof(struct window));
	if(!w)
		return NULL;
	unsigned int client_width = width - 10;
	unsigned int client_height = height - 10; 
	
	w->client_width = client_width;
	w->client_height = client_height;
	w->x = x;
	w->y = y;
	w->window_width = width;
	w->window_height = height;

	size_t framebuffer_size = w->backbuffer_size = width * height * (display_get_bpp() / 8);
	w->window_backbuffer = mmap(NULL, framebuffer_size,
		PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	
	if(w->window_backbuffer == MAP_FAILED)
	{
		perror("mmap");
		free(w);
		return NULL;
	}

	window_add(w);

	return w;
}

void draw_window(struct window *w)
{
	display_copy_rect(w->x, w->y, w->window_width,
		w->window_height, w->window_backbuffer);
}

void draw_windows(void)
{
	for(struct window *w = window_list; w != NULL; w = w->next)
	{
		draw_window(w);
	} 

}
