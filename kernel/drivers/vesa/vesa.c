/* Copyright 2016 Pedro Falcato

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <stdint.h>
#include <drivers/vesa.h>
#include <kernel/vmm.h>
#include <kernel/mm.h>
#include <multiboot.h>
#include <kernel/panic.h>
#include <string.h>
#include <assert.h>
#include <fonts.h>
extern struct bitmap_font font;
volatile unsigned char *framebuffer = NULL;
uint32_t framebuffer_pitch = 0;
uint32_t framebuffer_height = 0;
uint32_t framebuffer_width = 0;
uint32_t framebuffer_bpp = 0;
uint32_t framebuffer_pixelwidth = 0;
unsigned char* bitmap = NULL;
__attribute__((hot))
void draw_char(unsigned char c, int x, int y, int fgcolor, int bgcolor)
{
	prefetch((const void *)framebuffer,1,1);
	int cx,cy;
	int mask[8]={128,64,32,16,8,4,2,1};
	for(cy=0;cy<16;cy++){
		for(cx=0;cx<8;cx++){
			put_pixel(x+cx,y+cy-12,(bitmap+(int)c*16)[cy] & mask[cx] ? fgcolor:bgcolor);
		}
	}
}
__attribute__((hot))
void put_pixel(unsigned int x,unsigned int y, int color)
{
   	/* do not write memory outside the screen buffer, check parameters against the VBE mode info */
   	if (x> framebuffer_width || y>framebuffer_height) return;
   	if (x) x = (x*(framebuffer_bpp>>3));
   	if (y) y = (y*framebuffer_pitch);
   	volatile unsigned char *cTemp;
   	cTemp = &framebuffer[x+y];
   	cTemp[0] = color & 0xff;
   	cTemp[1] = (color>>8) & 0xff;
   	cTemp[2] = (color>>16) & 0xff;
}
void draw_square(int side,int x, int y, int color)
{
	for(int j = y; j < y + side;j++)
	{
		for(int i = x; i < x + side;i++)
		{
			put_pixel(i,j,color);
		}
	}
}
__attribute__((cold))
void vesa_init(multiboot_info_t* info)
{
	bitmap = (unsigned char *)font.Bitmap;
	framebuffer = (volatile unsigned char *) ((uint32_t)info->framebuffer_addr);
	framebuffer_pitch = info->framebuffer_pitch;
	framebuffer_bpp = info->framebuffer_bpp;
	framebuffer_width = info->framebuffer_width;
	framebuffer_height = info->framebuffer_height;
	framebuffer_pixelwidth = framebuffer_bpp / 8;
	assert(framebuffer_bpp == 32);
	/* Without this call to put_pixel, it doesn't draw anything. Weird Bug */
	put_pixel(0,100,0);
	prefetch((const void *)framebuffer,1,3);
}
void* vesa_get_framebuffer_addr()
{
	return (void *)framebuffer;
}
vid_mode_t* vesa_get_videomode()
{
	vid_mode_t *vidm = kmalloc(sizeof(vid_mode_t));
	vidm->width = framebuffer_width;
	vidm->height = framebuffer_height;
	vidm->bpp = framebuffer_bpp;
	return vidm;
}
