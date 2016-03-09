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
 * File: kernel.cpp
 *
 * Description: Main kernel file, contains the entry point and initialization
 *
 * Date: 30/1/2016
 *
 *
 **************************************************************************/
#include <stddef.h>
#include <stdint.h>
#include <kernel/sbrk.h>
#include <string.h>
#include <stdio.h>
#include <kernel/yield.h>
#include <multiboot.h>
#include <kernel/ElfLoader.h>
#include <kernel/vmm.h>
#include <kernel/tty.h>
#include <kernel/compiler.h>
#include <stdlib.h>
#include <kernel/timer.h>
#include <kernel/watchdog.h>
#include <kernel/pmm.h>
#include <kernel/sleep.h>
#include <kernel/fd.h>
#include <kernel/initrd.h>
#include <kernel/fs.h>
#include <kernel/vga.h>
#include <kernel/registers.h>
#include <kernel/scheduler.h>
#include <kernel/kheap.h>
#include <kernel/panic.h>
#include <kernel/kthread.h>
#include <drivers/serial.h>
#include <drivers/ps2.h>
#include <kernel/mm.h>
#include <kernel/rtc.h>
static Spartix::Watchdog* wt;
/* Function: init_arch()
 * Purpose: Initialize architecture specific features, should be hooked by the architecture the kernel will run on
 */
#define TERM_OK(str) \
                printf("[  "); \
		TTY::SetColor(make_color(COLOR_GREEN, COLOR_BLACK)); \
		printf("OK"); \
		TTY::SetColor(make_color(COLOR_LIGHT_GREY, COLOR_BLACK)); \
		printf("  ] "); \
		puts(str); \

ARCH_SPECIFIC void init_arch();
ARCH_SPECIFIC void init_vmm();
extern "C" void jump_userspace();
ARCH_SPECIFIC void InitKeyboard();
static multiboot_info_t* mbt;
static multiboot_memory_map_t*  mmap_arr[10];
static uint32_t initrd_addr;
extern uint32_t end;
extern char __BUILD_NUMBER;
static fs_node_t* initrd_root;
extern "C" void KernelEarly(multiboot_info_t* info, size_t magic)
{
	TTY::Init();
	if(info == nullptr)
		panic("Invalid multiboot_info_t*.The bootloader currently being used is broken");
	mbt = info;
	puts("Booting ...");

	// Check if the magic number is the same as the multiboot 1 spec
	if(magic == 0x2BADB002){
		TERM_OK("Spartix kernel booted by a Multiboot 1 compliant bootloader");
	}else
		panic("Bootloader not Multiboot 1 compliant"); // If not, panic, because our kernel relies on it
	init_arch();
	printf("Loaded by %s\n",mbt->boot_loader_name);
	mbt->mmap_addr+=0x80000000;

	multiboot_memory_map_t* mmap = (multiboot_memory_map_t*) mbt->mmap_addr;

	memset((void*)0x80200000,0,4096);

	PMM::Init(mbt->mem_lower + mbt->mem_upper,(uintptr_t) 0x80200000);
	// Initialize the Physical memory manager

	while((unsigned int)mmap < mbt->mmap_addr + mbt->mmap_length) {
		static int i = 0;
		mmap_arr [i] = mmap;
		if(mmap->type==MULTIBOOT_MEMORY_AVAILABLE)
		    PMM::Push(mmap->addr,mmap->len);
		i++;
		mmap = (multiboot_memory_map_t*) ( (unsigned int)mmap + mmap->size + sizeof(unsigned int) );
	}
	printf("Total memory: %i MiB\n",mbt->mem_lower+mbt->mem_upper/1024);
	multiboot_module_t* mod_start_ptr = (multiboot_module_t*)mbt->mods_addr;
	initrd_addr = mod_start_ptr->mod_start;
}
void KernelUserspace();
extern "C" void KernelMain()
{

	printf("Spartix kernel %s branch %s build %d\n",KERNEL_VERSION,KERNEL_BRANCH,&__BUILD_NUMBER);

	// Initialize the timer
	Timer::Init(1000);
	TERM_OK("Initialized the Timer");

	//Initialize the VMM
	VMM::Init();
	TERM_OK("Initialized the Virtual Memory Manager");

	// Initialize the kernel heap
	InitHeap();
	TERM_OK("Initialized the Kernel Heap");
	//Initialize the Initrd
	initrd_root = Initrd::Init(initrd_addr);

	if(!initrd_root)
		abort();
	//Initialize PS/2 keyboard drivers
	InitKeyboard();

	KThread* main = CreateThread(KernelUserspace);
	wt = new Spartix::Watchdog(main);
	main->Start();
	// Enable interrupts
	asm volatile("sti");

	for(;;)
	{
		asm volatile("hlt");
	}
}
void KernelUserspace()
{
	// Test kernel features

	// Test the timer
	TERM_OK("Testing the timer...");
	uint64_t time = Timer::GetTickCount();

	while(Timer::GetTickCount() == time)
	{
		asm volatile("hlt");
	}
	TERM_OK("Timer test successful");

	// Test Kheap
	TERM_OK("Testing the Kernel Heap...");

	void* test_ptr = kmalloc(4096); // Allocate 4 Kilobytes of memory

	if(!test_ptr)
		panic("Heap test failed");
	kfree(test_ptr);

	TERM_OK("Heap test successful");

	// Initialize less important drivers
	// Initalize Serial driver
	Serial::Init();
	Serial::WriteString("[  OK  ] Serial driver initialized");

	TERM_OK("Serial driver initialized");

	fs_node_t* node = finddir_fs(initrd_root,(char*)"/boot/Kernel.map");

	if(!node)
		abort();
	wt->Start();

	RTC::Init();
	for(;;)
	{
		asm volatile("hlt");
	}
}
