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
#include <multiboot2.h>
#include <stdio.h>
#include <kernel/vmm.h>
#include <kernel/Paging.h>
#include <kernel/pmm.h>
#include <kernel/idt.h>
#include <drivers/softwarefb.h>
#include <kernel/tty.h>
#include <kernel/panic.h>
#include <kernel/cpu.h>
#include <kernel/pit.h>
#include <drivers/ps2.h>
/* Function: init_arch()
 * Purpose: Initialize architecture specific features, should be hooked by the architecture the kernel will run on
 */
#if defined (__i386__)
	#define KERNEL_VIRTUAL_BASE 0xC0000000
#elif defined (__x86_64__)
	#define KERNEL_VIRTUAL_BASE 0xFFFFFFFF80000000
#endif
#define KERNEL_FB 0xFFFFE00000000000
void KernelLate();
void InitKeyboard();
extern uint64_t kernelEnd;
extern char __BUILD_NUMBER;
extern char __BUILD_DATE;
#define UNUSED_PARAMETER(x) (void)x
// Global TTY device, used by printf
TTY* global_terminal;
// First TTY device
static TTY firstTerminal;
extern "C" void KernelEarly(uintptr_t addr, uint32_t magic)
{
	addr += KERNEL_VIRTUAL_BASE;
	if (magic != MULTIBOOT2_BOOTLOADER_MAGIC)
	{
		return;
	}
	IDT::Init();
	struct multiboot_tag_framebuffer *tagfb = nullptr;
	for (struct multiboot_tag *tag = (struct multiboot_tag *)(addr + 8);tag->type != MULTIBOOT_TAG_TYPE_END;
		tag = (struct multiboot_tag *) ((multiboot_uint8_t *) tag + ((tag->size + 7) & ~7))) {
		size_t totalMemory = 0;
		switch(tag->type) {
			case MULTIBOOT_TAG_TYPE_BASIC_MEMINFO:
			{
				struct multiboot_tag_basic_meminfo *memInfo = (struct multiboot_tag_basic_meminfo *) tag;
				totalMemory = memInfo->mem_lower + memInfo->mem_upper;
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
			}
			case MULTIBOOT_TAG_TYPE_FRAMEBUFFER:
			{
				tagfb = (struct multiboot_tag_framebuffer *) tag;
			}
		}
	}
	VirtualMemoryManager::Init();
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
extern "C" void KernelMain()
{
	printf("Spartix kernel %s branch %s build %d for the %s architecture\n", KERNEL_VERSION,
	       KERNEL_BRANCH, &__BUILD_NUMBER, KERNEL_ARCH);
	printf("This kernel was built on %s, %d as integer\n", __DATE__, &__BUILD_DATE);
	// Identify the CPU it's running on (bootstrap CPU)
	CPU::Identify();
	CPU::InitInterrupts();
	PIT::Init(1000);
	asm volatile("sti");
	InitKeyboard();
	printf("PIT initialized!\n");
	printf("Keyboard initialized!\n");
	for (;;) {
		__asm__ __volatile__ ("hlt");
	}
}
void KernelLate()
{
	for (;;) {
		__asm__ __volatile__ ("hlt");
	}
}
