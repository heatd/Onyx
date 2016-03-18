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
#pragma once
#include <stdint.h>
#include <multiboot.h>
typedef struct vid_mode
{
	uint32_t width;
	uint32_t height;
	uint32_t bpp;
	vid_mode(uint32_t w,uint32_t h,uint32_t b)
	{
		width = w;
		height = h;
		bpp = b;
	}
}vid_mode_t;
namespace Vesa
{
	extern volatile unsigned char* framebuffer;
	extern uint32_t framebuffer_pitch;
	extern uint32_t framebuffer_width;
	extern uint32_t framebuffer_height;
	extern uint32_t framebuffer_bpp;
	extern uint32_t framebuffer_pixelwidth;
	void PutPixel(int x,int y, int color);
	void DrawSquare(int side,int x, int y, int color);
	void DrawString(const char* str,int x,int y);
	void DrawChar(unsigned char c, int x, int y, int fgcolor, int bgcolor);
	void Init(multiboot_info_t* info);
	void* GetFramebufferAddr();
	vid_mode_t* GetVideoMode();
}
