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
#ifdef __x86_64__
#include <multiboot2.h>
typedef multiboot_tag multiboot_info_t;
#else
#include <multiboot.h>
#endif
#include <kernel/vmm.h>
#include <kernel/tty.h>
#include <kernel/compiler.h>
#include <stdlib.h>
#include <kernel/timer.h>
#include <kernel/pmm.h>
#include <kernel/sleep.h>
#include <kernel/initrd.h>
#include <kernel/fs.h>
#include <kernel/registers.h>
#include <kernel/task_scheduler.h>
#include <kernel/kheap.h>
#include <kernel/panic.h>
#include <drivers/ps2.h>
#include <kernel/mm.h>
/* Function: init_arch()
 * Purpose: Initialize architecture specific features, should be hooked by the architecture the kernel will run on
 */
ARCH_SPECIFIC void init_arch();
ARCH_SPECIFIC void init_vmm();
extern "C" void jump_userspace();
ARCH_SPECIFIC void init_keyboard();
static multiboot_info_t* mbt;
static uint32_t initrd_addr;
extern uint32_t end;
extern "C" void KernelEarly(multiboot_info_t* info, size_t magic)
{
	if(info == NULL);
		//panic("Invalid multiboot_info_t*.The bootloader currently being used is broken");
	mbt = info;
	TTY::Init();
	puts("Booting ...");
	// Check if the magic number is the same as the multiboot 1 spec
	if(magic == 0x2BADB002)
		puts("Spartix kernel booted by a Multiboot 1 compliant bootloader");
	else
		panic("Bootloader not Multiboot 1 compliant"); // If not, panic, because our kernel relies on it 
	init_arch();
	
	mbt->mmap_addr+=0x80000000;
	multiboot_memory_map_t* mmap = (multiboot_memory_map_t*) mbt->mmap_addr;
	memset((void*)0x80200000,0,4096);
	PMM::Init(mbt->mem_lower + mbt->mem_upper,(uintptr_t) 0x80200000);
	multiboot_memory_map_t*  mmap_arr[10];
	while((unsigned int)mmap < mbt->mmap_addr + mbt->mmap_length) {
		static int i = 0;
		mmap_arr [i] = mmap;
		if(mmap->type==MULTIBOOT_MEMORY_AVAILABLE)
		    PMM::Push(mmap->addr,mmap->len);
		mmap = (multiboot_memory_map_t*) ( (unsigned int)mmap + mmap->size + sizeof(unsigned int) );
	}
	printf("Memory in KiB:%i\n",mbt->mem_lower+mbt->mem_upper);
	multiboot_module_t* mod_start_ptr = (multiboot_module_t*)mbt->mods_addr;
	initrd_addr = mod_start_ptr->mod_start;
}
extern "C" void KernelMain()
{
	puts("Spartix kernel 0.1");
	// Enable interrupts
	asm volatile("sti");
	// Initialize the timer
	Timer::Init(1000);
	//Initialize the VMM
	VMM::Init();
	// Initialize the kernel heap
	InitHeap();
	fs_node_t* initrd_root = Initrd::Init(initrd_addr);
	if(!initrd_root)
		abort();
	fs_node_t* node = finddir_fs(initrd_root,(char*)"boot/Kernel.map");
	if(!node)
		abort();
	init_keyboard();
	init_scheduler();
	preempt();
	
	for(;;)
	{
		asm volatile("hlt");
	}
}
