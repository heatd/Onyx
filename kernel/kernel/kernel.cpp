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
#include <kernel/yield.h>
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
#include <kernel/vga.h>
#include <kernel/registers.h>
#include <kernel/scheduler.h>
#include <kernel/kheap.h>
#include <kernel/panic.h>
#include <drivers/serial.h>
#include <drivers/ps2.h>
#include <kernel/mm.h>
/* Function: init_arch()
 * Purpose: Initialize architecture specific features, should be hooked by the architecture the kernel will run on
 */
#define TERM_OK(str) \
                printf("["); \
		TTY::SetColor(make_color(COLOR_GREEN, COLOR_BLACK)); \
		printf("OK"); \
		TTY::SetColor(make_color(COLOR_LIGHT_GREY, COLOR_BLACK)); \
		printf("] "); \
		puts(str); \

ARCH_SPECIFIC void init_arch();
ARCH_SPECIFIC void init_vmm();
extern "C" void jump_userspace();
ARCH_SPECIFIC void InitKeyboard();
static multiboot_info_t* mbt;
static multiboot_memory_map_t*  mmap_arr[10];
static uint32_t initrd_addr;
extern uint32_t end;
static fs_node_t* initrd_root;
extern "C" void KernelEarly(multiboot_info_t* info, size_t magic)
{
	TTY::Init();
	if(info == NULL)
		panic("Invalid multiboot_info_t*.The bootloader currently being used is broken");
	mbt = info;
	puts("Booting ...");
	
	// Check if the magic number is the same as the multiboot 1 spec
	if(magic == 0x2BADB002){
		TERM_OK("Spartix kernel booted by a Multiboot 1 compliant bootloader");
	}else
		panic("Bootloader not Multiboot 1 compliant"); // If not, panic, because our kernel relies on it 
	init_arch();
	
	mbt->mmap_addr+=0x80000000;
	
	multiboot_memory_map_t* mmap = (multiboot_memory_map_t*) mbt->mmap_addr;
	
	memset((void*)0x80200000,0,4096);
	
	PMM::Init(mbt->mem_lower + mbt->mem_upper,(uintptr_t) 0x80200000);

	
	while((unsigned int)mmap < mbt->mmap_addr + mbt->mmap_length) {
		static int i = 0;
		mmap_arr [i] = mmap;
		if(mmap->type==MULTIBOOT_MEMORY_AVAILABLE)
		    PMM::Push(mmap->addr,mmap->len);
		i++;
		mmap = (multiboot_memory_map_t*) ( (unsigned int)mmap + mmap->size + sizeof(unsigned int) );
	}
	printf("Total memory:%i MiB\n",mbt->mem_lower+mbt->mem_upper/1024);
	multiboot_module_t* mod_start_ptr = (multiboot_module_t*)mbt->mods_addr;
	initrd_addr = mod_start_ptr->mod_start;
}
void KernelUserspace();
extern "C" void KernelMain()
{
	puts("Spartix kernel 0.1");
	// Initialize the timer
	Timer::Init(1000);
	TERM_OK("Initialized the Timer");
	//Initialize the VMM
	VMM::Init();
	TERM_OK("Initialized the Virtual Memory Manager");
	// Initialize the kernel heap
	InitHeap();
	TERM_OK("Initialized the Kernel Heap");
	
	initrd_root = Initrd::Init(initrd_addr);
	
	if(!initrd_root)
		abort();
	
	InitKeyboard();
	
	Task_t* main_task = new Task_t;
	
	CreateTask(main_task,KernelUserspace);
	
	// Enable interrupts
	asm volatile("sti");
	for(;;)
	{
		asm volatile("hlt");
	}
}
void KernelUserspace()
{
	// Initialize less important drivers
	Serial::Init();
	
	Serial::WriteString("[OK] Serial driver initialized");
	
	TERM_OK("Serial driver initialized");
	
	fs_node_t* node = finddir_fs(initrd_root,(char*)"boot/Kernel.map");
	
	if(!node)
		abort();
	for(;;)
	{
		asm volatile("hlt");
	}
	
}