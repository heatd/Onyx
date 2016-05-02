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
#include <kernel/sbrk.h>
#include <string.h>
#include <stdio.h>
#include <kernel/yield.h>
#include <multiboot.h>
#include <kernel/elf_loader.h>
#include <kernel/vmm.h>
#include <kernel/tty.h>
#include <kernel/compiler.h>
#include <stdlib.h>
#include <kernel/timer.h>
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
#include <kernel/spinlock.h>
#include <unistd.h>
#include <drivers/vesa.h>
#include <kernel/process.h>
#include <kernel/devfs.h>
#include <ctype.h>
/* Function: init_arch()
 * Purpose: Initialize architecture specific features, should be hooked by the architecture the kernel will run on
 */
#if defined (__i386__)
	#define KERNEL_VIRTUAL_BASE 0xC0000000
#elif defined (__x86_64__)
	#define KERNEL_VIRTUAL_BASE 0xFFFFFFFF80000000
#endif
#define TERM_OK(str) \
                printf("[  "); \
		tty_set_color(0x00FF00); \
		printf("OK"); \
		tty_set_color(0xC0C0C0); \
		printf("  ] "); \
		puts(str); \

ARCH_SPECIFIC void init_arch();
void kernel_late();
ARCH_SPECIFIC void init_vmm();
extern void jump_userspace();
ARCH_SPECIFIC void init_keyboard();
multiboot_info_t *mbt;
static multiboot_memory_map_t *mmap_arr[10];
static uint32_t initrd_addr;
extern uint32_t end;
extern char __BUILD_NUMBER;
extern char __BUILD_DATE;
extern fs_node_t *fs_root;
void kernel_early(multiboot_info_t * info, size_t magic)
{
	mbt = info;
	mbt->mmap_addr += KERNEL_VIRTUAL_BASE;

	multiboot_memory_map_t *mmap =
	    (multiboot_memory_map_t *) mbt->mmap_addr;

	memset((void *) &end, 0, 4096);

	pmm_init(mbt->mem_lower + mbt->mem_upper, (uintptr_t) &end);
	/* Initialize the Physical memory manager */

	while ((unsigned int) mmap < mbt->mmap_addr + mbt->mmap_length) {
		static int i = 0;
		mmap_arr[i] = mmap;
		if (mmap->type == MULTIBOOT_MEMORY_AVAILABLE)
			pmm_push(mmap->addr, mmap->len);
		i++;
		mmap =
		    (multiboot_memory_map_t *) ((unsigned int) mmap +
						mmap->size +
						sizeof(unsigned int));
	}
	/*Initialize the VMM */
	vmm_init(mbt->framebuffer_addr);
	vesa_init(mbt);
	tty_init();
	puts("Booting ...");
	/* Check if the magic number is the same as the multiboot 1 spec */
	if (magic == 0x2BADB002) {
		TERM_OK
		    ("Spartix kernel booted by a Multiboot 1 compliant bootloader");
	} else
		panic("Bootloader not Multiboot 1 compliant");	/* If not, panic, because our kernel relies on it */
	init_arch();
	printf("Loaded by %s\n", mbt->boot_loader_name);
	printf("Total memory: %i MiB\n",
	       mbt->mem_lower + mbt->mem_upper / 1024);
	multiboot_module_t *mod_start_ptr =
	    (multiboot_module_t *) mbt->mods_addr;
	initrd_addr = mod_start_ptr->mod_start;
}
void kernel_main()
{

	printf("Spartix kernel %s branch %s build %d\n", KERNEL_VERSION,
	       KERNEL_BRANCH, &__BUILD_NUMBER);
	printf("Built on %d\n", &__BUILD_DATE);
	/* Initialize the timer */
	timer_init(1000);
	TERM_OK("Initialized the Timer");
	/* Initialize the kernel heap */
	init_heap();
	TERM_OK("Initialized the Kernel Heap");
	vmm_finish();
	/*Initialize the Initrd */
	fs_root = initrd_init(initrd_addr);

	if (!fs_root)
		panic("Could not allocate enough memory to allocate the \
		filesystem root\n");
	/*Initialize PS/2 keyboard drivers */
	init_keyboard();
	TERM_OK("Initializing multitasking");
	/* Start the first thread in the kernel.
	   The bootstrap thread never gets executed again,
	   so this thread will stop executing when we start kt
	   */
	kthread_t *kt = kthread_create(kernel_late, false);
	kthread_start(kt);

	for (;;) {
		__asm__ __volatile__ ("hlt");
	}
}
void test()
{
	printf("Failfish\n");
	printf("Current PID: %d\n",sys_getpid());
	while(1);
}
void kernel_late()
{
	TERM_OK("Multitasking Initialized");
	/* Test kernel features */
	/* Test the timer */
	TERM_OK("Testing the timer...");
	uint64_t time = timer_get_tick_count();
	while (timer_get_tick_count() == time) {
		__asm__ __volatile__ ("hlt");
	}
	TERM_OK("Timer test successful");
	/* Test Kheap */
	TERM_OK("Testing the Kernel Heap...");

	void *test_ptr = kmalloc(4096);	/* Allocate 4 Kilobytes of memory */

	if (!test_ptr)
		panic("Heap test failed");
	kfree(test_ptr);

	TERM_OK("Heap test successful");

	/* Initialize less important drivers */

	fs_node_t *node = finddir_fs(fs_root, (char *) "/boot/Kernel.map");

	if (!node)
		panic("Could not find the node\n");
	/* Initialize the devs ( /dev/ tree )*/
	devfs_init();

	/* Initalize Serial driver */
	serial_init();
	serial_write_string("serial0: Serial Driver initialized\n");

	TERM_OK("Serial driver initialized");

	process_init();

	process_t *daemon = process_create(0x500000,0x600000,NULL);
	if(!daemon) {
		panic("Fail\n");
	}
	kthread_t *kt = kthread_create(test,true);
	process_add_thread(daemon,kt);
	kthread_start(kt);
	for (;;) {
		__asm__ __volatile__ ("hlt");
	}
}
