/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
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
#include <multiboot2.h>
#include <stdio.h>
#include <kernel/vmm.h>
#include <kernel/Paging.h>
#include <kernel/kheap.h>
#include <kernel/pmm.h>
#include <kernel/idt.h>
#include <drivers/softwarefb.h>
#include <kernel/tty.h>
#include <kernel/panic.h>
#include <kernel/cpu.h>
#include <kernel/pit.h>
#include <drivers/ps2.h>
#include <kernel/vfs.h>
#include <kernel/initrd.h>
#include <new.h>
#include <drivers/pci.h>
#include <kernel/task_switching.h>
/* Function: init_arch()
 * Purpose: Initialize architecture specific features, should be hooked by the architecture the kernel will run on
 */
#define KERNEL_FB 0xFFFFE00000000000
void KernelLate(void*);
void InitKeyboard();
extern uint64_t kernelEnd;
extern char __BUILD_NUMBER;
extern char __BUILD_DATE;
#define UNUSED_PARAMETER(x) (void)x
// Global TTY device, used by printf
TTY* global_terminal;
// First TTY device
static TTY firstTerminal;
static struct multiboot_tag_module* initrd_tag = nullptr;
uintptr_t address = 0;
namespace __cxxabiv1
{
	/* guard variables */

	/* The ABI requires a 64-bit type.  */
	__extension__ typedef int __guard __attribute__((mode(__DI__)));
	/* All these calls are marked extern "C", so the compiler(gcc) can call them */
	extern "C" int __cxa_guard_acquire (__guard *);
	extern "C" void __cxa_guard_release (__guard *);
	extern "C" void __cxa_guard_abort (__guard *);
	extern "C" void __cxa_pure_virtual();
	extern "C" int __cxa_guard_acquire (__guard *g)
	{
		return !*(char *)(g);
	}

	extern "C" void __cxa_guard_release (__guard *g)
	{
		*(char *)g = 1;
	}

	extern "C" void __cxa_guard_abort (__guard *)
	{
		abort();
	}
	extern "C" void __cxa_pure_virtual()
	{
		panic("Error: Pure virtual call could not be made");
	}
}
extern "C" void KernelEarly(uintptr_t addr, uint32_t magic)
{
	addr += KERNEL_VIRTUAL_BASE;
	if (magic != MULTIBOOT2_BOOTLOADER_MAGIC)
	{
		return;
	}
	IDT::Init();
	struct multiboot_tag_framebuffer* tagfb = nullptr;
	size_t totalMemory = 0;
	for (struct multiboot_tag *tag = (struct multiboot_tag *)(addr + 8);tag->type != MULTIBOOT_TAG_TYPE_END;
		tag = (struct multiboot_tag *) ((multiboot_uint8_t *) tag + ((tag->size + 7) & ~7))) {
		switch(tag->type) {
			case MULTIBOOT_TAG_TYPE_BASIC_MEMINFO:
			{
				struct multiboot_tag_basic_meminfo *memInfo = (struct multiboot_tag_basic_meminfo *) tag;
				totalMemory = memInfo->mem_lower + memInfo->mem_upper;
				break;
			}
			case MULTIBOOT_TAG_TYPE_MMAP:
			{
				// Initialize the PMM stack KERNEL_VIRTUAL_BASE + 1MB. TODO: detect size of modules and calculate size from that
				PhysicalMemoryManager::Init(totalMemory, (uintptr_t)&kernelEnd + 0x100000);
				struct multiboot_tag_mmap *mmaptag = (struct multiboot_tag_mmap *) tag;
				size_t entries = mmaptag->size / mmaptag->entry_size;
				struct multiboot_mmap_entry *mmap = (struct multiboot_mmap_entry*)mmaptag->entries;
				for(size_t i = 0; i <= entries; i++) {
					if(mmap->type == MULTIBOOT_MEMORY_AVAILABLE) {
						PhysicalMemoryManager::Push(mmap->addr, mmap->len, 0x200000);
					}
					mmap++;
				}
				break;
			}
			case MULTIBOOT_TAG_TYPE_FRAMEBUFFER:
			{
				tagfb = (struct multiboot_tag_framebuffer *) tag;
				break;
			}
			case MULTIBOOT_TAG_TYPE_MODULE:
			{
				initrd_tag = (struct multiboot_tag_module*) tag;
				break;
			}
		}
	}
	VirtualMemoryManager::Init();
	Paging::MapAllPhys(totalMemory * 1024);
	// Map the FB
	for(uintptr_t virt = KERNEL_FB, phys = tagfb->common.framebuffer_addr; virt < KERNEL_FB + 0x400000; virt +=4096, phys+=4096)
	{
		// Use Paging:: directly, as we have no heap yet
		Paging::MapPhysToVirt(virt,phys, 0x3);
	}
	// Initialize the Software framebuffer
	SoftwareFramebuffer::Init(KERNEL_FB, tagfb->common.framebuffer_bpp, tagfb->common.framebuffer_width, tagfb->common.framebuffer_height, tagfb->common.framebuffer_pitch);
	// Initialize the first terminal
	firstTerminal.Init();
	global_terminal = &firstTerminal;
	printf("TTY Device initialized!\n");

}
VFS* vfs = nullptr;
void KernelLate2(void* args)
{
	(void) args;
	printf("hello\n");
	while(1);
}
extern void libc_late_init();
extern "C" void KernelMain()
{
	printf("Spartix kernel %s branch %s build %d for the %s architecture\n", KERNEL_VERSION,
	       KERNEL_BRANCH, &__BUILD_NUMBER, KERNEL_ARCH);
	printf("This kernel was built on %s, %d as integer\n", __DATE__, &__BUILD_DATE);
	// Identify the CPU it's running on (bootstrap CPU)
	CPU::Identify();
	CPU::InitInterrupts();
	PIT::Init(1000);
	InitKeyboard();

	printf("PIT initialized!\n");
	printf("Keyboard initialized!\n");

	int virtualAddressSpace = 0, physAddressSpace = 0;
	CPU::GetAddressSpaceSize(virtualAddressSpace, physAddressSpace);
	printf("Address space info:\n    Physical Address Bits: %d\n    Virtual Address Bits: %d\n"
		, virtualAddressSpace, physAddressSpace);

	// Start the Virtual address bookkeeping
	VirtualMemoryManager::StartAddressBookkeeping(KERNEL_FB);

	// Initialize the kernel heap
	InitHeap();

	//Initialize the VFS
	VFS* kvfs = new VFS;
	vfs = kvfs;
	printf("VFS initialized!\n");

	if(!initrd_tag)
		panic("Initrd not found\n");
	printf("Initrd module loaded at 0x%X\n",initrd_tag->mod_start);
	void *initrdAddress = reinterpret_cast<void *>(initrd_tag->mod_start + KERNEL_VIRTUAL_BASE);

	Initrd* initfs = new (initrdAddress) Initrd;
	initfs->LoadIntoRamfs();

	// Initalize Multitasking
	NativeSchedulerCreateThread(KernelLate, 1, (void*)"Started multitasking!");
	NativeSchedulerCreateThread(KernelLate2, 1, (void*)"Started multitasking2!");
	// Initialize Late LIBC
	libc_late_init();
	asm volatile("sti");
	for (;;) {
		__asm__ __volatile__ ("hlt");
	}
}
void KernelLate(void* args)
{
	/* At this point, multitasking is initialized in the kernel
	 * Perform a small test to check if the argument string was passed correctly,
	 * and continue with initialization */

	printf("%s\n",args);
	void* mem = VirtualMemoryManager::AllocateVirtAddress(VM_KERNEL, 1024);
	VirtualMemoryManager::MapRange(mem, 1024);
	// Create PTY
	global_terminal->CreatePTYAndSwitch(mem);
	printf("Created PTY0!\n");
	// Initialize PCI
	PCI::Init();

	for (;;) {
		__asm__ __volatile__ ("hlt");
	}
}
