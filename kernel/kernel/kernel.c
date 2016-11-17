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
#include <stdio.h>
#include <mbr.h>
#include <multiboot2.h>
#include <errno.h>

#include <kernel/vmm.h>
#include <kernel/paging.h>
#include <kernel/pmm.h>
#include <kernel/idt.h>
#include <kernel/tty.h>
#include <kernel/panic.h>
#include <kernel/cpu.h>
#include <kernel/pit.h>
#include <kernel/vfs.h>
#include <kernel/initrd.h>
#include <kernel/task_switching.h>
#include <kernel/elf.h>
#include <kernel/tss.h>
#include <kernel/heap.h>
#include <kernel/acpi.h>
#include <kernel/power_management.h>
#include <kernel/udp.h>
#include <kernel/dhcp.h>
#include <kernel/modules.h>
#include <kernel/ethernet.h>
#include <kernel/random.h>

#include <drivers/ps2.h>
#include <drivers/ata.h>
#include <drivers/ext2.h>
#include <drivers/rtc.h>
#include <drivers/e1000.h>
#include <drivers/softwarefb.h>
#include <drivers/pci.h>
/* Function: init_arch()
 * Purpose: Initialize architecture specific features, should be hooked by the architecture the kernel will run on
 */
void kernel_multitasking(void *);
extern uint64_t kernel_end;
#define KERNEL_START_PHYS 0x100000
#define KERNEL_START_VIRT (KERNEL_VIRTUAL_BASE + KERNEL_START_PHYS)
extern char __BUILD_NUMBER;
extern char __BUILD_DATE;
static struct multiboot_tag_module *initrd_tag = NULL;
uintptr_t address = 0;
struct multiboot_tag_elf_sections secs;
struct multiboot_tag_mmap *mmap_tag = NULL;
void *initrd_addr = NULL;
static void *tramp = NULL;

void kernel_early(uintptr_t addr, uint32_t magic)
{
	addr += PHYS_BASE;
	if (magic != MULTIBOOT2_BOOTLOADER_MAGIC)
		return;
	idt_init();
	vmm_init();
	
	paging_map_all_phys(0x8000000000);
	struct multiboot_tag_framebuffer *tagfb = NULL;
	size_t total_mem = 0;
	size_t initrd_size = 0;
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
				initrd_size = initrd_tag->size;
				break;
			}
		case MULTIBOOT_TAG_TYPE_ELF_SECTIONS:
		{
			memcpy(&secs, tag, sizeof(struct multiboot_tag_elf_sections));
			break;
		}
		}
	}
	pmm_init(total_mem, (uintptr_t) &kernel_end);
	size_t entries = mmap_tag->size / mmap_tag->entry_size;
	struct multiboot_mmap_entry *mmap = (struct multiboot_mmap_entry *) mmap_tag->entries;
	uintptr_t end_kernel = (uintptr_t) &kernel_end;
	initrd_size += end_kernel - KERNEL_START_VIRT;
	initrd_size += 0x1000;
	initrd_size &= 0xFFFFFFFFFFFFF000;
	for (size_t i = 0; i <= entries; i++)
	{
		if (mmap->type == MULTIBOOT_MEMORY_AVAILABLE)
		{
			pmm_push(mmap->addr, mmap->len, 0x200000 + initrd_size);
		}
		mmap++;
	}
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
	initrd_addr = (void*) (uintptr_t) initrd_tag->mod_start;
}
uintptr_t rsdp;
extern void libc_late_init();
void kernel_main()
{
	/* Identify the CPU it's running on (bootstrap CPU) */
	cpu_identify();
	
	/* Map the first bucket's memory address */
	void *mem = (void*)0xFFFFFFF890000000;
	vmm_map_range(mem, 1024, VMM_GLOBAL | VMM_WRITE | VMM_NOEXEC);
	
	/* Initialize the heap */
	heap_init(mem, 16, 64, 128, 256, 512);
	
	/* Find the RSDP(needed for ACPI and ACPICA) */
	for(int i = 0; i < 0x100000/16; i++)
	{
		if(!memcmp((char*)(PHYS_BASE + 0x000E0000 + i * 16),(char*)"RSD PTR ", 8))
		{	
			char *addr = (char*)(PHYS_BASE + 0x000E0000 + i * 16);
			rsdp = addr - (char*)PHYS_BASE;
			break;
		}
	}
	/* Initialize ACPI */
	acpi_initialize();

	/* Intialize the interrupt part of the CPU (arch dependent) */
	cpu_init_interrupts();
	printf("Trampoline code at: %p\n", tramp);
	extern uintptr_t _start_smp;
	extern uintptr_t _end_smp;
	memcpy((void*)tramp, &_start_smp, (uintptr_t)&_end_smp - (uintptr_t)&_start_smp);
	
	int cpus = cpu_init_mp();
	extern void init_keyboard();
	init_keyboard();
	
	/* Initialize the kernel heap */
	init_tss();
	
	/* Initialize the VFS */
	vfs_init();
	if (!initrd_tag)
		panic("Initrd not found\n");
	initrd_addr = (void*)((char*) initrd_addr + PHYS_BASE);
	
	/* Invalidate and unmap the lower memory zones (0x0 to 0x400000) */
	asm volatile("movq $0, pdlower; movq $0, pdlower + 8;invlpg 0x0;invlpg 0x200000");
	/* Initialize the initrd */
	init_initrd(initrd_addr);
	
	/* Initalize multitasking */
	sched_create_thread(kernel_multitasking, 1, NULL);
	/* Initialize late libc */
	libc_late_init();
	asm volatile ("sti");
	for (;;)
	{
		__asm__ __volatile__("hlt");
	}
}
extern int exec(const char *, char**, char**);
uintptr_t rsdp;
void kernel_multitasking(void *arg)
{
	void *mem = vmm_allocate_virt_address(VM_KERNEL, 1024, VMM_TYPE_REGULAR, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	vmm_map_range(mem, 1024, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	/* Create PTY */
	tty_create_pty_and_switch(mem);
	printf(ANSI_COLOR_GREEN "Spartix kernel %s branch %s build %d for the %s architecture\n" ANSI_COLOR_RESET,
	     KERNEL_VERSION, KERNEL_BRANCH, &__BUILD_NUMBER, KERNEL_ARCH);
	printf("This kernel was built on %s, %d as integer\n", __DATE__, &__BUILD_DATE);
	/* Initialize PCI */
	pci_init();
	/*extern void init_elf_symbols(struct multiboot_tag_elf_sections *);
	init_elf_symbols(&secs);*/
	initialize_ata();

	char *args[] = {"/etc/fstab", NULL};
	char *envp[] = {"PATH=/bin:/usr/bin:/usr/lib", NULL};
	init_ext2drv();
	initialize_module_subsystem();
	init_rtc();
	/*if(ethernet_init())
		printf("eth0: failed to find a compatible device\n");
	else
		printf("eth0: found compatible device\n");*/
	//dhcp_initialize();
	/*read_partitions();
	vfsnode_t *in = open_vfs(fs_root, "/etc/fstab");
	if (!in)
	{
		printf("%s: %s\n", "/etc/fstab", strerror(errno));
		return errno = ENOENT;
	}
	char *b = malloc(in->size);
	memset(b, 0, in->size);
	write_vfs(0, in->size, b, in);*/
	initialize_entropy();
	exec("/sbin/init", args, envp);
	for (;;) asm volatile("hlt");
}