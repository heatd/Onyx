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
/**************************************************************************
 * 
 * 
 * File: kernel.c
 * 
 * Description: Main kernel file, contains the entry point and initialization
 * 
 * Date: 30/1/2016
 * 
 * 
 **************************************************************************/

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#ifdef AMD64
#include <multiboot2.h>
typedef multiboot_info_t multiboot_tag_structure
#else
#include <multiboot.h>
#endif
#include <kernel/tty.h>
#include <kernel/compiler.h>
#include <stdlib.h>
/* Function: init_arch()
 * Purpose: Initialize architecture specific features, should be hooked by the architecture the kernel will run on
 */
ARCH_SPECIFIC void init_arch();
static multiboot_info_t* mbt;
void kernel_early(multiboot_info_t* info, size_t magic)
{
	if(info == NULL)
		panic("Invalid multiboot_info_t*.The bootloader currently being used is broken");
	terminal_initialize();
	puts("Booting ...");
	if(magic == 0x2BADB002)
		puts("Kernel booted by a Multiboot 1 compliant bootloader");
	else
		abort();
	init_arch();
}
void kernel_main()
{
	puts("Spartix kernel 0.1");
	while(1)
	{
		asm volatile("hlt");
	}
}
