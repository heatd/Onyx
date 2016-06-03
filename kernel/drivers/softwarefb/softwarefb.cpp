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
#include <stdint.h>
#include <drivers/softwarefb.h>
#include <kernel/vmm.h>
#include <kernel/mm.h>
#include <kernel/panic.h>
#include <string.h>
#include <assert.h>
#include <../kernel/fonts/font.cpp>
volatile unsigned char *framebuffer = nullptr;
uint32_t framebuffer_pitch = 0;
uint32_t framebuffer_height = 0;
uint32_t framebuffer_width = 0;
uint32_t framebuffer_bpp = 0;
uint32_t framebuffer_pixelwidth = 0;
unsigned char *bitmap = nullptr;
namespace SoftwareFramebuffer
{

__attribute__((hot))
void DrawChar(unsigned char c, int x, int y, int fgcolor, int bgcolor, void* fb)
{
	prefetch((const void *)fb,1,1);
	int cx,cy;
	int mask[8]={128,64,32,16,8,4,2,1};
	for(cy=0;cy<16;cy++){
		for(cx=0;cx<8;cx++){
			PutPixel(x+cx,y+cy-12,(bitmap+(int)c*16)[cy] & mask[cx] ? fgcolor:bgcolor,fb);
		}
	}
}
__attribute__((hot))
void PutPixel(unsigned int x,unsigned int y, int color, void* fb)
{
	if(fb ==(uint64_t*)0xDEADDEAD)
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
void DrawSquare(int side,int x, int y, int color)
{
	for(int j = y; j < y + side;j++)
	{
		for(int i = x; i < x + side;i++)
		{
			PutPixel(i,j,color, (void*)framebuffer);
		}
	}
}
__attribute__((cold))
void Init(uintptr_t fb_address, uint32_t bpp, uint32_t width, uint32_t height,uint32_t pitch)
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
	PutPixel(0,100,0,(void*)0xDEADDEAD);
	prefetch((const void *)framebuffer,1,3);
}
void* GetFBAddress()
{
	return (void *)framebuffer;
}
static VideoMode vidm = {0,0,0};
VideoMode *GetVideomode()
{
	if( vidm.width == 0 ) {
		vidm.width = framebuffer_width;
		vidm.height = framebuffer_height;
		vidm.bpp = framebuffer_bpp;
	}
	return &vidm;
}
void Scroll(void* fb)
{
	unsigned char* second_line = ( unsigned char *)fb + framebuffer_pitch * 16;
	memmove((void *)fb,second_line,0x400000 - framebuffer_pitch * 16 - framebuffer_pixelwidth * framebuffer_width);
}
};
