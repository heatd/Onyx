/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _DISPLAY_H
#define _DISPLAY_H

#include <drm/drm.h>

void display_fill_rect(void *fb, unsigned int x, unsigned int y, unsigned int width,
	unsigned int height, uint32_t color);
void display_copy_rect(unsigned int x, unsigned int y, unsigned int width, unsigned int height,
	void *backbuffer);
unsigned int display_get_bpp(void);

#endif
