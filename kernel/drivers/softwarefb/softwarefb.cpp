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
void DrawChar(unsigned char c, int x, int y, int fgcolor, int bgcolor)
{
	prefetch((const void *)framebuffer,1,1);
	int cx,cy;
	int mask[8]={128,64,32,16,8,4,2,1};
	for(cy=0;cy<16;cy++){
		for(cx=0;cx<8;cx++){
			PutPixel(x+cx,y+cy-12,(bitmap+(int)c*16)[cy] & mask[cx] ? fgcolor:bgcolor);
		}
	}
}
__attribute__((hot))
void PutPixel(unsigned int x,unsigned int y, int color)
{
   	/* do not write memory outside the screen buffer, check parameters against the framebuffer info */
   	if (x > framebuffer_width || y > framebuffer_height) return;
   	if (x) x = (x * (framebuffer_bpp>>3));
   	if (y) y = (y * framebuffer_pitch);
   	volatile unsigned char *cTemp;
   	cTemp = &framebuffer[x + y];
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
			PutPixel(i,j,color);
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
	PutPixel(0,100,0);
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
void Scroll()
{
	unsigned char *second_line = ( unsigned char *)framebuffer;
	second_line += framebuffer_pitch * 20;
	memmove((void *)framebuffer,second_line,0x400000 - framebuffer_pixelwidth * framebuffer_width +
	framebuffer_pitch * 16);
}
};