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
}vid_mode_t;
void put_pixel(int x,int y, int color);
void draw_square(int side,int x, int y, int color);
void draw_string(const char* str,int x,int y);
void draw_char(unsigned char c, int x, int y, int fgcolor, int bgcolor);
void vesa_init(multiboot_info_t* info);
void* vesa_get_framebuffer_addr();
vid_mode_t* vesa_get_videomode();
