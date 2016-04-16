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
#ifndef _FB_H
#define _FB_H


typedef volatile unsigned char _fb;
typedef _fb *framebuffer_t;
void fb_swap(framebuffer_t fb);
void fb_destroy(framebuffer_t fb);
framebuffer_t fb_create();

#endif
