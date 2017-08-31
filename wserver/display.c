/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stddef.h>
#include <stdint.h>

#include <display.h>

#include <drm/drm.h>

static struct drm_fb *main_fb = NULL;

void display_set_framebuffer(struct drm_fb *fb)
{
	main_fb = fb;
}

void display_fill_rect(void *_fb, unsigned int x, unsigned int y, unsigned int width, unsigned int height,
	uint32_t color)
{
	size_t bits_per_row = _fb == main_fb->framebuffer ? main_fb->pitch : width * (display_get_bpp() / 8);
	volatile unsigned char *__fb = (volatile unsigned char *) _fb;
	__fb += (y * bits_per_row) + x * (main_fb->bpp/8);
	volatile uint32_t *fb = (volatile uint32_t *) __fb;

	for(size_t i = 0; i < height; i++)
	{
		for(size_t j = 0; j < width; j++)
			fb[j] = color;
		fb = (volatile uint32_t *) ((char*) fb + bits_per_row);
	}
}

void display_copy_rect(unsigned int x, unsigned int y, unsigned int width, unsigned int height,
	void *bb)
{
	volatile unsigned char *__fb = main_fb->framebuffer;
	__fb += (y * main_fb->pitch) + x * (main_fb->bpp/8);
	volatile uint32_t *fb = (volatile uint32_t *) __fb;
	volatile uint32_t *backbuffer = (volatile uint32_t *) bb;

	for(size_t i = 0; i < height; i++)
	{
		for(size_t j = 0; j < width; j++)
			fb[j] = *backbuffer++;
		fb = (volatile uint32_t *) ((char*) fb + main_fb->pitch);
	}
}

unsigned int display_get_bpp(void)
{
	return main_fb->bpp;
}
