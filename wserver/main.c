/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <stdbool.h>
#include <fcntl.h>

#include <display.h>
#include <window.h>
#include <drm/drm.h>

#include <sys/mman.h>

int main(int argc, char **argv, char **envp)
{
	printf("wserver - window server\n");

	if(drm_initialize() < 0)
		err(1, "Could not initialize DRM");

	struct drm_videomode mode;

	if(drm_get_videomode(&mode) < 0)
		err(1, "Could not get video mode");

	struct drm_dumb_buffer_info *buffer = malloc(sizeof(*buffer));

	if(!buffer)
		err(1, "Could not allocate buffer struct");

	buffer->width = mode.width;
	buffer->height = mode.height;
	buffer->bpp = mode.bpp;

	if(drm_create_dumb_buffer(buffer) < 0)
		err(1, "Could not create dumb buffer");

	struct drm_create_buf_map_args args;
	args.handle = buffer->handle;
	args.offset = 0;

	if(drm_create_buffer_map(&args) < 0)
		err(1, "Could not setup mapping");
	
	void *pointer = mmap(NULL, buffer->size, PROT_READ | PROT_WRITE, MAP_SHARED, drm_get_fd(), 0);
	if(!pointer)
		err(1, "mmap: Could not mmap dumb buffer");

	display_fill_rect(pointer, 0, 0, buffer->width, buffer->height, 0xaaaaaa);

	/*struct window *win = window_create(40, 40, 640, 480);
	assert(win != NULL);

	display_fill_rect(win->window_backbuffer, 0, 0, win->window_width, win->window_height,
		0x808080);
	int fd = shm_open("wserver-00", O_RDWR | O_CREAT, 0666);

	ftruncate(fd, 4096);

	while(true)
	{
		draw_windows();
	}*/

	while(1)
	{
		if(drm_swap_buffers(buffer->handle) < 0)
			err(1, "drm_swap_buffers");
	}

	return 0;
}
