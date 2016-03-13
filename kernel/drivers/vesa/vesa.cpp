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
#include <multiboot.h>
#include <kernel/panic.h>
#include <string.h>
#include <assert.h>
#include <fonts.h>
namespace Vesa
{
volatile unsigned char* framebuffer = nullptr;
uint32_t framebuffer_pitch = 0;
uint32_t framebuffer_height = 0;
uint32_t framebuffer_width = 0;
uint32_t framebuffer_bpp = 0;
uint32_t framebuffer_pixelwidth = 0;
extern "C" struct bitmap_font font;
unsigned char* bitmap = nullptr;
void DrawChar(unsigned char c, int x, int y, int fgcolor, int bgcolor)
{
	int cx,cy;
	int mask[8]={128,64,32,16,8,4,2,1};
	for(cy=0;cy<16;cy++){
		for(cx=0;cx<8;cx++){
			PutPixel(x+cx,y+cy-12,(bitmap+(int)c*16)[cy] & mask[cx] ? fgcolor:bgcolor);
		}
	}
}
void PutPixel(int x,int y, int color)
{
   	//do not write memory outside the screen buffer, check parameters against the VBE mode info
   	if (x<0 || x> framebuffer_width || y<0 || y>framebuffer_height) return;
   	if (x) x = (x*(framebuffer_bpp>>3));
   	if (y) y = (y*framebuffer_pitch);
   	volatile unsigned char* cTemp;
   	cTemp = &framebuffer[x+y];
   	cTemp[0] = color & 0xff;
   	cTemp[1] = (color>>8) & 0xff;
   	cTemp[2] = (color>>16) & 0xff;
}
void DrawSquare(int side,int x, int y, int color)
{
	for(int j = y; j < y + side;j++)
	{
		for(int i = x; i < x + side;i++)
		{
			PutPixel(i,j,0xFFFF00);
		}
	}
}
void DrawString(const char* str,int x,int y)
{
	size_t len = strlen(str);
	for(size_t i,j = 0; i < len;i++,j+=8)
	{
		DrawChar(str[i],j,y,0xC0C0C0,0);
	}
}
void Init(multiboot_info_t* info)
{
	bitmap = (unsigned char*)font.Bitmap;
	Vesa::framebuffer = (unsigned char*) info->framebuffer_addr;
	asm volatile("movl %0,%%eax"::"r"(Vesa::framebuffer));
	Vesa::framebuffer_pitch = info->framebuffer_pitch;
	Vesa::framebuffer_bpp = info->framebuffer_bpp;
	Vesa::framebuffer_width = info->framebuffer_width;
	Vesa::framebuffer_height = info->framebuffer_height;
	Vesa::framebuffer_pixelwidth = framebuffer_bpp / 8;
	assert(Vesa::framebuffer_bpp == 32);
	// Without this call to PutPixel, it doesn't draw anything. Weird Bug
	PutPixel(0,100,0);
}
}
