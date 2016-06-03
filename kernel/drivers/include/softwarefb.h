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
#ifndef _VESA_H
#define _VESA_H
#include <stdint.h>
#include <multiboot2.h>
typedef struct vid_mode
{
	uint32_t width;
	uint32_t height;
	uint32_t bpp;
}VideoMode;
namespace SoftwareFramebuffer
{
	void PutPixel(unsigned int x,unsigned int y, int color, void* fb);
	void DrawSquare(int side,int x, int y, int color);
	void DrawChar(unsigned char c, int x, int y, int fgcolor, int bgcolor, void* fb);
	void Init(uintptr_t fb_address, uint32_t bpp, uint32_t width, uint32_t height,uint32_t pitch);
	void *GetFBAddress();
	void Scroll();
	VideoMode *GetVideomode();
}
#endif
