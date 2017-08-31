/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <fonts.h>

#include <kernel/compiler.h>
#include <kernel/video.h>
#include <kernel/vmm.h>
#include <kernel/kernelinfo.h>
#include <kernel/panic.h>

#include <drivers/softwarefb.h>

void *memcpy_fast(void *dst, void *src, size_t n);
volatile unsigned char *framebuffer = NULL;
static uint32_t framebuffer_pitch = 0;
static uint32_t framebuffer_height = 0;
static uint32_t framebuffer_width = 0;
static uint32_t framebuffer_bpp = 0;
static uint32_t framebuffer_pixelwidth = 0;
struct video_ops softfb_ops =
{
	.get_fb = softfb_getfb,
	.draw_cursor = softfb_draw_cursor,
	.draw_char = softfb_draw_char,
	.get_videomode = softfb_getvideomode,
	.scroll = softfb_scroll
};
struct video_device softfb_device = 
{
	.ops = &softfb_ops,
	.driver_string = OS_NAME OS_RELEASE OS_VERSION "softfb driver",
	.card_string = "softfb",
	.status = VIDEO_STATUS_INSERTED,
	.refcount = 0
};
static inline void put_pixel(unsigned int x,unsigned int y, int color, void* fb)
{
	if(unlikely(fb == (uint64_t*) 0xDEADDEAD))
		fb = (void*) framebuffer;
	/* do not write memory outside the screen buffer, check parameters against the framebuffer info */
	x = (x * (framebuffer_bpp>>3));
	y = (y * framebuffer_pitch);
	
	volatile unsigned int *pixel = (volatile unsigned int *)&((char*)fb)[x + y];
	*pixel = color;
}
unsigned char *bitmap = NULL;
__attribute__((hot))
void softfb_draw_char(unsigned char c, int x, int y, int fgcolor, int bgcolor, void* fb)
{
	int cx,cy;
	int mask[8]={128,64,32,16,8,4,2,1};
	for(cy=0;cy<16;cy++)
	{
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
	for(cy=0;cy<16;cy++)
	{
		for(cx=0;cx<8;cx++)
		{
			put_pixel(x+cx,y+cy-12,(__cursor__bitmap)[cy] & mask[cx] ? fgcolor:bgcolor,fb);
		}
	}
}
extern struct bitmap_font font;
__attribute__((cold))
void softfb_init(uintptr_t fb_address, uint32_t bpp, uint32_t width, uint32_t height,uint32_t pitch)
{
	bitmap = (unsigned char *) font.Bitmap;
	framebuffer = (volatile unsigned char*) fb_address;
	framebuffer_pitch = pitch;
	framebuffer_bpp = bpp;
	framebuffer_width = width;
	framebuffer_height = height;
	framebuffer_pixelwidth = bpp / 8;

	prefetch((const void *)framebuffer, 1, 3);
	video_set_main_adapter(&softfb_device);
}
void* softfb_getfb(struct video_device *dev)
{
	UNUSED(dev);
	return (void *)framebuffer;
}
static struct video_mode vidm = {0, 0, 0, 0};
struct video_mode *softfb_getvideomode(struct video_device *dev)
{
	UNUSED(dev);
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
	unsigned char* second_line = ( unsigned char *) fb + framebuffer_pitch * 16;
	memcpy_fast((void *) fb, second_line, (0x400000 - framebuffer_pitch * 16 - framebuffer_pixelwidth * framebuffer_width));
}
