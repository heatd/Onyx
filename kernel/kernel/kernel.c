/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
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
#include <string.h>
#include <fcntl.h>
#include <pthread_kernel.h>
#include <partitions.h>

#include <sys/mman.h>

#include <kernel/slab.h>
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
#include <kernel/dev.h>
#include <kernel/bootmem.h>
#include <kernel/log.h>
#include <kernel/dns.h>
#include <kernel/icmp.h>
#include <kernel/process.h>
#include <kernel/envp.h>
#include <kernel/block.h>
#include <kernel/elf.h>

#include <drivers/ps2.h>
#include <drivers/ata.h>
#include <drivers/ext2.h>
#include <drivers/rtc.h>
#include <drivers/e1000.h>
#include <drivers/softwarefb.h>
#include <drivers/pci.h>

#define KERNEL_START_VIRT 0xffffffff80100000

extern uint64_t kernel_end;
extern char __BUILD_NUMBER;
extern char __BUILD_DATE;
extern uintptr_t _start_smp;
extern uintptr_t _end_smp;
 
static struct multiboot_tag_module *initrd_tag = NULL;
struct multiboot_tag_elf_sections *secs;
struct multiboot_tag_mmap *mmap_tag = NULL;
void *initrd_addr = NULL;
static void *tramp = NULL;
void *phys_fb = NULL;
char kernel_cmdline[256];
uintptr_t address = 0;
uintptr_t rsdp;

extern void libc_late_init();
extern void init_keyboard();
extern int exec(const char *, char**, char**);

char *kernel_arguments[200];
int kernel_argc = 0;
void kernel_parse_command_line(char *cmd)
{
	char *original_string = cmd;
	while(*cmd)
	{
		if(*cmd == '-') /* Found an argument */
		{
			char *token = strchr(cmd, ' ');
			if(!token)
				token = original_string + strlen(original_string);
			size_t size_token = (size_t)(token - cmd);
			char *new_string = malloc(size_token + 1);
			memset(new_string, 0, size_token + 1);
			memcpy(new_string, cmd, size_token);
			kernel_arguments[kernel_argc] = new_string;
			kernel_argc++;
			cmd += size_token -1;
		}
		cmd++;
	}
}
char *kernel_getopt(char *opt)
{
	for(int i = 0; i < kernel_argc; i++)
	{
		if(memcmp(kernel_arguments[i], opt, strlen(opt)) == 0)
		{
			/* We found the argument, retrieve the value */
			if(strlen(opt) == strlen(kernel_arguments[i])) /* if len(opt) == len(kargs[i]),
			 the argument has no value (or the caller fucked up) */
				return opt;
			char *parse = kernel_arguments[i] + strlen(opt);
			if(*parse == '=')
				return ++parse;
			if(*parse == ' ')
				return ++parse;
		}
	}
	ERROR("kernel", "%s: no such argument\n", opt);
	return NULL;
}
extern PML4 *current_pml4;
int find_and_exec_init(char **argv, char **envp)
{
	char *path = "/sbin/init";
retry:;
	vfsnode_t *in = open_vfs(fs_root, path);
	if(!in)
	{
		if(!strcmp(path, "/bin/init"))
			panic("No init program found!\n");
		path = "/bin/init";
		goto retry;
	}
	process_t *proc = process_create(path, NULL, NULL);
	if(!proc)
		return errno = ENOMEM, -1;
	char *buffer = malloc(in->size);
	if (!buffer)
		return errno = ENOMEM;
	read_vfs(0, in->size, buffer, in);
	
	void *entry = elf_load((void *) buffer);
	
	char **env = copy_env_vars(envp);
	
	int argc;
	char **args = copy_argv(argv, path, &argc);
	
	proc->cr3 = current_pml4;
	proc->tree = vmm_get_tree();

	current_process = proc;
	/* Setup stdio */
	proc->ctx.file_desc[0] = malloc(sizeof(file_desc_t));
	proc->ctx.file_desc[0]->vfs_node = open_vfs(slashdev, "/dev/tty");
	proc->ctx.file_desc[0]->seek = 0;
	proc->ctx.file_desc[0]->flags = O_RDONLY;
	proc->ctx.file_desc[1] = malloc(sizeof(file_desc_t));
	proc->ctx.file_desc[1]->vfs_node = open_vfs(slashdev, "/dev/tty");
	proc->ctx.file_desc[1]->seek = 0;
	proc->ctx.file_desc[1]->flags = O_WRONLY;
	proc->ctx.file_desc[2] = malloc(sizeof(file_desc_t));
	proc->ctx.file_desc[2]->vfs_node = open_vfs(slashdev, "/dev/tty");
	proc->ctx.file_desc[2]->seek = 0;
	proc->ctx.file_desc[2]->flags = O_WRONLY;
	// Allocate space for %fs TODO: Do this while in elf_load, as we need the TLS size
	uintptr_t *fs = vmm_allocate_virt_address(0, 1, VMM_TYPE_REGULAR, VMM_WRITE | VMM_NOEXEC | VMM_USER);
	vmm_map_range(fs, 1, VMM_WRITE | VMM_NOEXEC | VMM_USER);
	pthread_t *p = (struct pthread*) fs;
	p->self = (pthread_t*) fs;
	proc->fs = (uintptr_t) fs;
	DISABLE_INTERRUPTS();
	process_create_thread(proc, (thread_callback_t) entry, 0, argc, args, env);
	// Ugh, a really bad hack to put it here. The ELF loader/execve needs to be restructered
	/* Setup the auxv at the stack bottom */
	Elf64_auxv_t *auxv = (Elf64_auxv_t *) proc->threads[0]->user_stack_bottom;
	unsigned char *scratch_space = (unsigned char *) (auxv + 37);
	for(int i = 0; i < 38; i++)
	{
		if(i != 0)
			auxv[i].a_type = i;
		if(i == 37)
			auxv[i].a_type = 0;
		switch(i)
		{
			case AT_PAGESZ:
				auxv[i].a_un.a_val = PAGE_SIZE;
				break;
			case AT_UID:
				auxv[i].a_un.a_val = proc->uid;
				break;
			case AT_GID:
				auxv[i].a_un.a_val = proc->gid;
				break;
			case AT_RANDOM:
				get_entropy((char*) scratch_space, 16);
				printf("Random: %x%x\n", *(uint64_t*) scratch_space, *(uint64_t*) scratch_space+1);
				scratch_space += 16;
				break;
		}
	}
	registers_t *regs = (registers_t *) proc->threads[0]->kernel_stack;
	regs->rcx = (uintptr_t) auxv;
	p->tid = proc->threads[0]->id;
	p->pid = proc->pid;
	free(buffer);
	free(in);
	ENABLE_INTERRUPTS();
	return 0;
}
void kernel_early(uintptr_t addr, uint32_t magic)
{
	addr += PHYS_BASE;
	if (magic != MULTIBOOT2_BOOTLOADER_MAGIC)
		return;
	idt_init();
	vmm_init();
	paging_map_all_phys();
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
				struct multiboot_tag_basic_meminfo *memInfo = (struct multiboot_tag_basic_meminfo *) tag;
				total_mem = memInfo->mem_lower + memInfo->mem_upper;
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
				tagfb = (struct multiboot_tag_framebuffer *) tag;
				break;
			}
		case MULTIBOOT_TAG_TYPE_MODULE:
			{
				initrd_tag = (struct multiboot_tag_module *) tag;
				initrd_size = initrd_tag->size;
				break;
			}
		case MULTIBOOT_TAG_TYPE_ELF_SECTIONS:
		{
			secs = (struct multiboot_tag_elf_sections *) tag;
			break;
		}
		case MULTIBOOT_TAG_TYPE_CMDLINE:
		{
			struct multiboot_tag_string *t = (struct multiboot_tag_string *) tag;
			strcpy(kernel_cmdline, t->string);
			break;
		}
		}
	}
	bootmem_init(total_mem, (uintptr_t) &kernel_end);

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
			bootmem_push(mmap->addr, mmap->len, 0x1000000 + initrd_size);
		}
		mmap++;
	}
	phys_fb = (void*) tagfb->common.framebuffer_addr;
	/* Map the FB */
	for (uintptr_t virt = KERNEL_FB, phys = tagfb->common.framebuffer_addr; virt < KERNEL_FB + 0x400000; virt += 4096, phys += 4096)
	{
		paging_map_phys_to_virt(virt, phys, VMM_GLOBAL | VMM_WRITE | VMM_NOEXEC);
	}

	/* Initialize the Software framebuffer */
	softfb_init(KERNEL_FB, tagfb->common.framebuffer_bpp, tagfb->common.framebuffer_width, tagfb->common.framebuffer_height, tagfb->common.framebuffer_pitch);

	/* Initialize the first terminal */
	tty_init();
	initrd_addr = (void*) (uintptr_t) initrd_tag->mod_start;

	/* Identify the CPU it's running on (bootstrap CPU) */
	cpu_identify();

	/* Map the first bucket's memory address */
	void *mem = (void*)0xFFFFFFF890000000;
	vmm_map_range(mem, 1024, VMM_GLOBAL | VMM_WRITE | VMM_NOEXEC);

	/* We need to get some early boot rtc data and initialize the entropy, as it's vital to initialize
	 * some entropy sources for the memory map */
	early_boot_rtc();
	initialize_entropy();

	vmm_start_address_bookkeeping(KERNEL_FB, 0xFFFFFFF890000000);

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
}
void kernel_multitasking(void *);
void kernel_main()
{
	init_elf_symbols(secs);

	/* Initialize ACPI */
	acpi_initialize();

	/* Intialize the interrupt part of the CPU (arch dependent) */
	cpu_init_interrupts();

	printf("Trampoline code at: %p\n", tramp);

	memcpy((void*)tramp, &_start_smp, (uintptr_t)&_end_smp - (uintptr_t)&_start_smp);

	/* Initialize multi-processors */
	cpu_init_mp();

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

	DISABLE_INTERRUPTS();
	/* Initialize the scheduler */
	if(sched_init())
		panic("sched: failed to initialize!");

	/* Initalize multitasking */
	sched_create_thread(kernel_multitasking, 1, NULL);
	/* Initialize late libc */
	libc_late_init();

	ENABLE_INTERRUPTS();
	for (;;)
	{
		__asm__ __volatile__("hlt");
	}
}

void kernel_multitasking(void *arg)
{
	void *mem = vmm_allocate_virt_address(VM_KERNEL, 1024, VMM_TYPE_REGULAR, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	vmm_map_range(mem, 1024, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	/* Create PTY */
	tty_create_pty_and_switch(mem);
	LOG("kernel", ANSI_COLOR_GREEN "Spartix kernel %s branch %s build %d for the %s architecture\n" ANSI_COLOR_RESET,
	     KERNEL_VERSION, KERNEL_BRANCH, &__BUILD_NUMBER, KERNEL_ARCH);
	LOG("kernel", "Command line: %s\n", kernel_cmdline);
	pci_init();
	
	/* Initialize devfs */
	devfs_init();

	pci_initialize_drivers();

	char *args[] = {"/etc/fstab", NULL};
	char *envp[] = {"PATH=/bin:/usr/bin:/usr/lib", NULL};
	init_ext2drv();
	initialize_module_subsystem();
	init_rtc();

	/* Initialize the network-related subsystems(the ones that need it) */
	
	/* Initialize dhcp */
	dhcp_initialize();

	/* Initialize DNS */
	dns_init();
	
	/* Initialize ICMP */
	icmp_init();
	
	/* Just a little demo for the recent DNS and ICMP features */
	//uint32_t ip = dns_resolve_host("www.google.com");
	//icmp_ping(ip, 10);

	/* Parse the command line string to a more friendly argv-like buffer */
	kernel_parse_command_line(kernel_cmdline);

	LOG("kernel", "root device %s\n", kernel_getopt("--root"));
	/*vfsnode_t *in = open_vfs(fs_root, "/etc/fstab");
	if (!in)
	{
		printf("%s: %s\n", "/etc/fstab", strerror(errno));
		return errno = ENOENT;
	}
	char *b = malloc(in->size);
	memset(b, 0, in->size);*/
	//write_vfs(0, in->size, b, in);
	//printf("%s\n", b);
	//sched_create_thread(test, 1, NULL);

	/* Start populating /dev */
	tty_create_dev(); /* /dev/tty */
	null_init(); /* /dev/null */
	zero_init(); /* /dev/zero */

	/* Mount the root partition */
	char *root_partition = kernel_getopt("--root");
	if(!root_partition)
		panic("--root wasn't specified in the kernel arguments");

	/* Note that we don't actually allocate an extra byte for the NUL terminator, since the partition number will
	 become just that */
	char *device_name = malloc(strlen(root_partition));
	if(!device_name)
		panic("Out of memory while allocating ´device_name´");

	strcpy(device_name, root_partition);
	/* Zero-terminate the string */
	device_name[strlen(root_partition)-1] = '\0';

	/* Search for it */
	block_device_t *dev = blkdev_search(device_name);
	if(!dev)
		panic("Root device not found!");

	find_and_exec_init(args, envp);
	if(errno == ENOENT)
	{
		panic("/sbin/init not found!");
	}

	get_current_thread()->status = THREAD_SLEEPING;
	for (;;) asm volatile("hlt");
}
