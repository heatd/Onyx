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
	struct drm_info *info;
	printf("wserver - window server\n");

	if(drm_initialize(&info) < 0)
		err(1, "Could not initialize DRM\n");

	struct drm_fb *fb = drm_map_fb();
	if(!fb)
		err(1, "Could not map the framebuffer\n");

	display_set_framebuffer(fb);
	display_fill_rect((void*) fb->framebuffer, 0, 0, fb->width, fb->height, 0);

	struct window *win = window_create(40, 40, 640, 480);
	assert(win != NULL);

	display_fill_rect(win->window_backbuffer, 0, 0, win->window_width, win->window_height,
		0x808080);
	int fd = shm_open("wserver-00", O_RDWR | O_CREAT, 0666);

	ftruncate(fd, 4096);

	while(true)
	{
		draw_windows();
	}

	return 0;
}
