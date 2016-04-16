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
#include <string.h>
#include <kernel/mm.h>
#include <drivers/vesa.h>
#include <kernel/fb.h>

framebuffer_t fb_create()
{
	vid_mode_t *vidm = vesa_get_videomode();
	/* Framebuffer size calculations go like this:
		The formula is:
			height * width * bpp = size (in bits)
			size in bytes = size/8
		Therefor: size of 1024 * 768 * 32: x/8 (where x is the result of height * width * bpp)
	*/
	return kmalloc(vidm->height * vidm->width * vidm->bpp / 8);
}
void fb_destroy(framebuffer_t fb)
{
	kfree((char *)fb);
}
void fb_swap(framebuffer_t fb)
{
	framebuffer_t vidmem = vesa_get_framebuffer_addr();
	vid_mode_t *vidm = vesa_get_videomode();
	if (fb == vidmem) {
		return;
	}
	memcpy((char *)vidmem,(char *)fb, vidm->height * vidm->width * vidm->bpp / 8);
}
