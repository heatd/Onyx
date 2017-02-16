/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdint.h>
#include <drivers/softwarefb.h>
#include <kernel/vmm.h>
#include <kernel/panic.h>
#include <string.h>
#include <assert.h>
#include <fonts.h>
volatile unsigned char *framebuffer = NULL;
uint32_t framebuffer_pitch = 0;
uint32_t framebuffer_height = 0;
uint32_t framebuffer_width = 0;
uint32_t framebuffer_bpp = 0;
uint32_t framebuffer_pixelwidth = 0;
unsigned char *bitmap = NULL;
__attribute__((hot))
void softfb_draw_char(unsigned char c, int x, int y, int fgcolor, int bgcolor, void* fb)
{
	int cx,cy;
	int mask[8]={128,64,32,16,8,4,2,1};
	for(cy=0;cy<16;cy++){
		for(cx=0;cx<8;cx++)
		{
			put_pixel(x+cx,y+cy-12,(bitmap+(int)c*16)[cy] & mask[cx] ? fgcolor:bgcolor,fb);
		}
	}
}
extern unsigned char __cursor__bitmap[];
__attribute__((hot))
void softfb_draw_cursor(int x, int y, int fgcolor, int bgcolor, void* fb)
{
	int cx,cy;
	int mask[8]={128,64,32,16,8,4,2,1};
	prefetch((const void *)&mask,1,1);
	for(cy=0;cy<16;cy++){
		for(cx=0;cx<8;cx++){
			put_pixel(x+cx,y+cy-12,(__cursor__bitmap)[cy] & mask[cx] ? fgcolor:bgcolor,fb);
		}
	}
}
__attribute__((hot))
void put_pixel(unsigned int x,unsigned int y, int color, void* fb)
{
	if(fb == (uint64_t*)0xDEADDEAD)
		fb = (void*)framebuffer;
   	/* do not write memory outside the screen buffer, check parameters against the framebuffer info */
   	if (x > framebuffer_width || y > framebuffer_height) return;
   	if (x) x = (x * (framebuffer_bpp>>3));
   	if (y) y = (y * framebuffer_pitch);
   	volatile unsigned char *cTemp = (volatile unsigned char*)fb;
   	cTemp = &cTemp[x + y];
   	cTemp[0] = color & 0xff;
   	cTemp[1] = (color >> 8) & 0xff;
   	cTemp[2] = (color >> 16) & 0xff;
}
extern struct bitmap_font font;
__attribute__((cold))
void softfb_init(uintptr_t fb_address, uint32_t bpp, uint32_t width, uint32_t height,uint32_t pitch)
{
	bitmap = (unsigned char *)font.Bitmap;
	framebuffer = (volatile unsigned char*)fb_address;
	framebuffer_pitch = pitch;
	framebuffer_bpp = bpp;
	framebuffer_width = width;
	framebuffer_height = height;
	framebuffer_pixelwidth = bpp / 8;
	assert(framebuffer_bpp == 32);
	/* Without this call to PutPixel, it doesn't draw anything. Weird Bug */
	put_pixel(0,100,0,(void*)0xDEADDEAD);
	prefetch((const void *)framebuffer,1,3);
}
void* softfb_getfb()
{
	return (void *)framebuffer;
}
static videomode_t vidm = {0, 0, 0, 0};
videomode_t *softfb_getvideomode()
{
	if( vidm.width == 0 ) {
		vidm.width = framebuffer_width;
		vidm.height = framebuffer_height;
		vidm.bpp = framebuffer_bpp;
		vidm.pitch = framebuffer_pitch;
	}
	return &vidm;
}
void softfb_scroll(void* fb)
{
	unsigned char* second_line = ( unsigned char *)fb + framebuffer_pitch * 16;
	memmove((void *)fb,second_line,(0x400000 - framebuffer_pitch * 16 - framebuffer_pixelwidth * framebuffer_width));
}
