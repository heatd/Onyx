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
	void PutPixel(unsigned int x,unsigned int y, int color);
	void DrawSquare(int side,int x, int y, int color);
	void DrawChar(unsigned char c, int x, int y, int fgcolor, int bgcolor);
	void Init(uintptr_t fb_address, uint32_t bpp, uint32_t width, uint32_t height,uint32_t pitch);
	void *GetFBAddress();
	void Scroll();
	VideoMode *GetVideomode();
}
#endif
