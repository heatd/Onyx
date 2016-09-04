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
#include <kernel/paging.h>
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
#include <drivers/pci.h>
#include <kernel/task_switching.h>
#include <kernel/elf.h>
#include <kernel/tss.h>
#include <drivers/ata.h>
#include <mbr.h>
#include <drivers/ext2.h>
#include <kernel/heap.h>
#include <acpi.h>
static const ACPI_EXCEPTION_INFO    AcpiGbl_ExceptionNames_Env[] =
{
    EXCEP_TXT ((char*)"AE_OK",                         (char*)"No error"),
    EXCEP_TXT ((char*)"AE_ERROR",                      (char*)"Unspecified error"),
    EXCEP_TXT ((char*)"AE_NO_ACPI_TABLES",             (char*)"ACPI tables could not be found"),
    EXCEP_TXT ((char*)"AE_NO_NAMESPACE",               (char*)"A namespace has not been loaded"),
    EXCEP_TXT ((char*)"AE_NO_MEMORY",                  (char*)"Insufficient dynamic memory"),
    EXCEP_TXT ((char*)"AE_NOT_FOUND",                 (char*) "A requested entity is not found"),
    EXCEP_TXT ((char*)"AE_NOT_EXIST",                  (char*)"A required entity does not exist"),
    EXCEP_TXT ((char*)"AE_ALREADY_EXISTS",             (char*)"An entity already exists"),
    EXCEP_TXT ((char*)"AE_TYPE",                       (char*)"The object type is incorrect"),
    EXCEP_TXT ((char*)"AE_NULL_OBJECT",               (char*) "A required object was missing"),
    EXCEP_TXT ((char*)"AE_NULL_ENTRY",                 (char*)"The requested object does not exist"),
    EXCEP_TXT ((char*)"AE_BUFFER_OVERFLOW",            (char*)"The buffer provided is too small"),
    EXCEP_TXT ((char*)"AE_STACK_OVERFLOW",             (char*)"An internal stack overflowed"),
    EXCEP_TXT ((char*)"AE_STACK_UNDERFLOW",            (char*)"An internal stack underflowed"),
    EXCEP_TXT ((char*)"AE_NOT_IMPLEMENTED",            (char*)"The feature is not implemented"),
    EXCEP_TXT ((char*)"AE_SUPPORT",                   (char*) "The feature is not supported"),
    EXCEP_TXT ((char*)"AE_LIMIT",                     (char*) "A predefined limit was exceeded"),
    EXCEP_TXT ((char*)"AE_TIME",                       (char*)"A time limit or timeout expired"),
    EXCEP_TXT ((char*)"AE_ACQUIRE_DEADLOCK",           (char*)"Internal error, attempt was made to acquire a mutex in improper order"),
    EXCEP_TXT ((char*)"AE_RELEASE_DEADLOCK",           (char*)"Internal error, attempt was made to release a mutex in improper order"),
    EXCEP_TXT ((char*)"AE_NOT_ACQUIRED",               (char*)"An attempt to release a mutex or Global Lock without a previous acquire"),
    EXCEP_TXT ((char*)"AE_ALREADY_ACQUIRED",           (char*)"Internal error, attempt was made to acquire a mutex twice"),
    EXCEP_TXT ((char*)"AE_NO_HARDWARE_RESPONSE",       (char*)"Hardware did not respond after an I/O operation"),
    EXCEP_TXT ((char*)"AE_NO_GLOBAL_LOCK",             (char*)"There is no FACS Global Lock"),
    EXCEP_TXT ((char*)"AE_ABORT_METHOD",               (char*)"A control method was aborted"),
    EXCEP_TXT ((char*)"AE_SAME_HANDLER",              (char*) "Attempt was made to install the same handler that is already installed"),
    EXCEP_TXT ((char*)"AE_NO_HANDLER",                (char*) "A handler for the operation is not installed"),
    EXCEP_TXT ((char*)"AE_OWNER_ID_LIMIT",             (char*)"There are no more Owner IDs available for ACPI tables or control methods"),
    EXCEP_TXT ((char*)"AE_NOT_CONFIGURED",             (char*)"The interface is not part of the current subsystem configuration"),
    EXCEP_TXT ((char*)"AE_ACCESS",                     (char*)"Permission denied for the requested operation")
};
/* Function: init_arch()
 * Purpose: Initialize architecture specific features, should be hooked by the architecture the kernel will run on
 */
void kernel_multitasking(void *);
extern uint64_t kernel_end;
extern char __BUILD_NUMBER;
extern char __BUILD_DATE;
#define UNUSED_PARAMETER(x) (void)x
static struct multiboot_tag_module *initrd_tag = NULL;
uintptr_t address = 0;
struct multiboot_tag_elf_sections *secs = NULL;
struct multiboot_tag_mmap *mmap_tag = NULL;
void kernel_early(uintptr_t addr, uint32_t magic)
{
	addr += KERNEL_VIRTUAL_BASE;
	if (magic != MULTIBOOT2_BOOTLOADER_MAGIC) {
		return;
	}
	idt_init();
	struct multiboot_tag_framebuffer *tagfb = NULL;
	size_t total_mem = 0;
	for (struct multiboot_tag * tag =
	     (struct multiboot_tag *)(addr + 8);
	     tag->type != MULTIBOOT_TAG_TYPE_END;
	     tag =
	     (struct multiboot_tag *) ((multiboot_uint8_t *) tag +
				       ((tag->size + 7) & ~7))) {
		switch (tag->type) {
		case MULTIBOOT_TAG_TYPE_BASIC_MEMINFO:
			{
				struct multiboot_tag_basic_meminfo *memInfo
				    =
				    (struct multiboot_tag_basic_meminfo *)
				    tag;
				total_mem =
				    memInfo->mem_lower +
				    memInfo->mem_upper;
				break;
			}
		case MULTIBOOT_TAG_TYPE_MMAP:
			{
				/* Initialize the PMM stack KERNEL_VIRTUAL_BASE + 1MB. TODO: detect size of modules and calculate size from that */
				mmap_tag = (struct multiboot_tag_mmap *) tag;
				break;
			}
		case MULTIBOOT_TAG_TYPE_FRAMEBUFFER:
			{
				tagfb =
				    (struct multiboot_tag_framebuffer *)
				    tag;
				break;
			}
		case MULTIBOOT_TAG_TYPE_MODULE:
			{
				initrd_tag =
				    (struct multiboot_tag_module *) tag;
				break;
			}
		case MULTIBOOT_TAG_TYPE_ELF_SECTIONS:
		{
			secs = (struct multiboot_tag_elf_sections *)tag;
			break;
		}
		}
	}
	pmm_init(total_mem, (uintptr_t) &kernel_end);
	size_t entries = mmap_tag->size / mmap_tag->entry_size;
	struct multiboot_mmap_entry *mmap = (struct multiboot_mmap_entry *) mmap_tag->entries;
	for (size_t i = 0; i <= entries; i++)
	{
		if (mmap->type == MULTIBOOT_MEMORY_AVAILABLE)
		{
			pmm_push(mmap->addr, mmap->len, 0x200000);
		}
		mmap++;
	}
	vmm_init();
	paging_map_all_phys(total_mem * 1024);
	/* Map the FB */
	for (uintptr_t virt = KERNEL_FB, phys =
	     tagfb->common.framebuffer_addr; virt < KERNEL_FB + 0x400000;
	     virt += 4096, phys += 4096) {
		/* Use Paging:: directly, as we have no heap yet */
		paging_map_phys_to_virt(virt, phys, VMM_GLOBAL | VMM_WRITE | VMM_NOEXEC);
	}

	/* Initialize the Software framebuffer */
	softfb_init(KERNEL_FB, tagfb->common.framebuffer_bpp,
				  tagfb->common.framebuffer_width,
				  tagfb->common.framebuffer_height,
				  tagfb->common.framebuffer_pitch);
	/* Initialize the first terminal */
	tty_init();
}
extern void libc_late_init();
void kernel_main()
{
	/* Identify the CPU it's running on (bootstrap CPU) */
	cpu_identify();
	cpu_init_interrupts();

	void *mem = (void*)0xFFFFFFF890000000;
	vmm_map_range(mem, 1024, VMM_GLOBAL | VMM_WRITE | VMM_NOEXEC);
	heap_init (mem, 16, 64, 128, 256, 512);
	pit_init(1000);
	extern void init_keyboard();
	init_keyboard();
	/* Initialize the kernel heap */
	init_tss();
	vfs_init();
	if (!initrd_tag)
		panic("Initrd not found\n");
	void *initrd_address = (void*)(initrd_tag->mod_start + PHYS_BASE);
	asm volatile("movq $0, pdlower;invlpg 0x0");
	/* Initialize the initrd */
	init_initrd(initrd_address);

	/* Initalize multitasking */
	sched_create_thread(kernel_multitasking, 1,
				    (void *) "Started multitasking!");
	/* Initialize late libc */
	libc_late_init();
	asm volatile ("sti");
	for (;;) {
		__asm__ __volatile__("hlt");
	}
}
extern int exec(const char *, char**);
char *pathsep = "/";
uintptr_t rsdp;
void kernel_multitasking(void *arg)
{
	/* At this point, multitasking is initialized in the kernel
	 * Perform a small test to check if the argument string was passed correctly,
	 * and continue with initialization */
	void *mem =
	    vmm_allocate_virt_address(VM_KERNEL, 1024, VMM_TYPE_REGULAR, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	vmm_map_range(mem, 1024, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	/* Create PTY */
	tty_create_pty_and_switch(mem);
	/*
	printf("Spartix kernel %s branch %s build %d for the %s architecture\n",
	     KERNEL_VERSION, KERNEL_BRANCH, &__BUILD_NUMBER, KERNEL_ARCH);
	printf("This kernel was built on %s, %d as integer\n", __DATE__, &__BUILD_DATE);*/
	/* Initialize PCI */
	pci_init();
	
	extern void init_elf_symbols(struct multiboot_tag_elf_sections *);
	init_elf_symbols(secs);
	initialize_ata();

	char *args[] = {"/usr/include/dirent.h", NULL};
	//init_ext2drv();
	//read_partitions();
	exec("/bin/cat", args);
	for (;;) asm volatile("hlt");
}
