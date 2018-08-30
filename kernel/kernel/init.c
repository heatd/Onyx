/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
/**************************************************************************
 *
 *
 * File: init.c
 *
 * Description: Main init file, contains the entry point and initialization
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
#include <assert.h>

#include <sys/mman.h>
#include <acpica/acpi.h>

#include <onyx/debug.h>
#include <onyx/slab.h>
#include <onyx/vm.h>
#include <onyx/paging.h>
#include <onyx/pmm.h>
#include <onyx/idt.h>
#include <onyx/tty.h>
#include <onyx/panic.h>
#include <onyx/cpu.h>
#include <onyx/pit.h>
#include <onyx/vfs.h>
#include <onyx/initrd.h>
#include <onyx/task_switching.h>
#include <onyx/binfmt.h>
#include <onyx/elf.h>
#include <onyx/tss.h>
#include <onyx/heap.h>
#include <onyx/acpi.h>
#include <onyx/power_management.h>
#include <onyx/udp.h>
#include <onyx/dhcp.h>
#include <onyx/modules.h>
#include <onyx/ethernet.h>
#include <onyx/random.h>
#include <onyx/dev.h>
#include <onyx/bootmem.h>
#include <onyx/log.h>
#include <onyx/dns.h>
#include <onyx/icmp.h>
#include <onyx/process.h>
#include <onyx/block.h>
#include <onyx/elf.h>
#include <onyx/smbios.h>
#include <onyx/fscache.h>
#include <onyx/page.h>
#include <onyx/irq.h>
#include <onyx/vdso.h>
#include <onyx/timer.h>
#include <onyx/worker.h>
#include <onyx/utils.h>
#include <onyx/sysfs.h>
#include <onyx/pagecache.h>
#include <onyx/driver.h>
#include <onyx/rwlock.h>
#include <onyx/crypt/sha256.h>
#include <onyx/clock.h>
#include <onyx/percpu.h>
#include <onyx/drm.h>

#include <drivers/ps2.h>
#include <drivers/ata.h>
#include <drivers/ext2.h>
#include <drivers/e1000.h>
#include <drivers/softwarefb.h>
#include <pci/pci.h>

extern uint64_t kernel_end;
extern uintptr_t _start_smp;
extern uintptr_t _end_smp;

void vt_init_blink(void);
void *initrd_addr = NULL;
void *tramp = NULL;
void *phys_fb = NULL;
char kernel_cmdline[256];
uintptr_t address = 0;

extern void libc_late_init();

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
			if(!new_string)
			{
				ERROR("kernel", "failed parsing: out of memory\n");
			}

			memset(new_string, 0, size_token + 1);
			memcpy(new_string, cmd, size_token);
			kernel_arguments[kernel_argc] = new_string;
			kernel_argc++;
			cmd += size_token -1;
		}
		cmd++;
	}
}

char *get_kernel_cmdline(void)
{
	return kernel_cmdline;
}

void set_initrd_address(void *initrd_address)
{
	initrd_addr = initrd_address;
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


void *process_setup_auxv(void *buffer, struct process *process);

extern PML4 *current_pml4;
int find_and_exec_init(char **argv, char **envp)
{
	char *path = "/sbin/init";
retry:;
	struct inode *in = open_vfs(get_fs_root(), path);
	if(!in)
	{
		printk("%s: Not found\n", path);
		perror("open_vfs");
		if(!strcmp(path, "/bin/init"))
		{
			perror("open");
			panic("No init program found!\n");
		}
		path = "/bin/init";
		goto retry;
	}
	struct process *proc = process_create(path, NULL, NULL);
	if(!proc)
		return errno = ENOMEM, -1;

	proc->address_space.cr3 = get_current_pml4();
	proc->address_space.tree = NULL;
 
	get_current_thread()->owner = proc;
	/* Setup stdio */
	proc->ctx.file_desc[0] = malloc(sizeof(file_desc_t));
	if(!proc->ctx.file_desc[0])
	{
		panic("kernel: out of memory while loading init(file descriptor 0)!\n");
	}
	
	proc->ctx.file_desc[0]->vfs_node = open_vfs(get_fs_root(), "/dev/tty");
	if(!proc->ctx.file_desc[0]->vfs_node)
	{
		perror("kernel: ");
		panic("Could not open tty\n");
	}

	proc->ctx.file_desc[0]->seek = 0;
	proc->ctx.file_desc[0]->flags = O_RDONLY;
	proc->ctx.file_desc[1] = malloc(sizeof(file_desc_t));
	if(!proc->ctx.file_desc[1])
	{
		panic("kernel: out of memory while loading init(file descriptor 1)!\n");
	}
	proc->ctx.file_desc[1]->vfs_node = open_vfs(get_fs_root(), "/dev/tty");
	proc->ctx.file_desc[1]->seek = 0;
	proc->ctx.file_desc[1]->flags = O_WRONLY;
	proc->ctx.file_desc[2] = malloc(sizeof(file_desc_t));
	if(!proc->ctx.file_desc[2])
	{
		panic("kernel: out of memory while loading init(file descriptor 2)!\n");
	}
	proc->ctx.file_desc[2]->vfs_node = open_vfs(get_fs_root(), "/dev/tty");
	proc->ctx.file_desc[2]->seek = 0;
	proc->ctx.file_desc[2]->flags = O_WRONLY;

	/* Read the file signature */
	unsigned char *buffer = malloc(100);
	if (!buffer)
		return errno = ENOMEM;
	read_vfs(0, 0, 100, buffer, in);

	argv[0] = path;
	/* Prepare the argument struct */
	struct binfmt_args args = {0};
	args.file_signature = buffer;
	args.filename = path;
	args.file = in;
	args.argv = argv;
	args.envp = envp;

	struct process *current = get_current_process();
	current->address_space.brk = map_user(vm_gen_brk_base(), 0x20000000, VM_TYPE_HEAP,
	VM_WRITE | VM_NOEXEC | VM_USER);
	current->address_space.mmap_base = vm_gen_mmap_base();

	/* Finally, load the binary */
	void *entry = load_binary(&args);

	assert(entry != NULL);

	int argc;
	char **_argv = process_copy_envarg(argv, false, &argc);
	char **_env = process_copy_envarg(envp, false, NULL);

	process_create_thread(proc, (thread_callback_t) entry, 0, argc, _argv, _env);

	Elf64_auxv_t *auxv = process_setup_auxv(current->threads[0]->user_stack_bottom, current);
	registers_t *regs = (registers_t *) current->threads[0]->kernel_stack;
	regs->rcx = (uintptr_t) auxv;
	
	uintptr_t *fs = get_user_pages(VM_TYPE_REGULAR, 1, VM_WRITE | VM_NOEXEC | VM_USER);
	current->threads[0]->fs = (void*) fs;
	__pthread_t *p = (__pthread_t*) fs;
	p->self = (__pthread_t*) fs;
	p->tid = get_current_process()->threads[0]->id;
	p->pid = get_current_process()->pid;

	sched_start_thread(current->threads[0]);

	return 0;
}

void kernel_multitasking(void *);
__attribute__((no_sanitize_undefined))
void kernel_main()
{

	/* Initialize ACPI */
	acpi_initialize();

	/* Initialize the interrupt part of the CPU (arch dependent) */
	cpu_init_interrupts();

	memcpy((void*) (PHYS_BASE + (uintptr_t) tramp), &_start_smp,
		(uintptr_t) &_end_smp - (uintptr_t)&_start_smp);

	/* Initialize multi-processors */
	cpu_init_mp();

	/* Initialize percpu vars */
	setup_percpu();

	init_tss();
	/* Initialize the VFS */
	vfs_init();

	if(!initrd_addr)
		panic("Initrd not found");
	initrd_addr = (void*)((char*) initrd_addr + PHYS_BASE);

	/* Initialize the initrd */
	init_initrd(initrd_addr);

	DISABLE_INTERRUPTS();

	/* Initialize the scheduler */
	if(sched_init())
		panic("sched: failed to initialize!");

	/* Initalize multitasking */
	thread_t *new_thread = sched_create_thread(kernel_multitasking, 1, NULL);

	assert(new_thread);

	vt_init_blink();

	/* Initialize late libc */
	libc_late_init();

	/* Initialize the IRQ worker thread */
	irq_init();

	/* Initialize the cache sync thread */
	pagecache_init();

	/* Start the new thread */
	sched_start_thread(new_thread);

	ENABLE_INTERRUPTS();
	for (;;);
}

void do_ktests(void);

void kernel_multitasking(void *arg)
{
	LOG("kernel", "Command line: %s\n", kernel_cmdline);

	/* Initialize the SMBIOS subsystem */
	smbios_init();

	/* Initialize the PCI subsystem */
	pci_init();

	/* Initialize devfs */
	devfs_init();

	/* Initialize drm */
	drm_init();

	/* Initialize each device driver */
	driver_init();

	/* Initialize the module subsystem */
	initialize_module_subsystem();

	/* Initialize power management */
	pm_init();

	/* Initialize the network-related subsystems(the ones that need it) */

	/* Initialize dhcp */
	//dhcp_initialize();
	/* Initialize DNS */
	dns_init();

	/* Initialize ICMP */
	//icmp_init();

	/* Parse the command line string to a more friendly argv-like buffer */
	kernel_parse_command_line(kernel_cmdline);

	/* Start populating /dev */
	tty_create_dev(); /* /dev/tty */
	null_init(); /* /dev/null */
	zero_init(); /* /dev/zero */
	entropy_init_dev(); /* /dev/random and /dev/urandom */
	
	/* Initialize the worker thread */
	worker_init();

	/* Initialize sysfs */
	sysfs_init();

	/* Populate /sys */
	vm_sysfs_init();

#ifdef CONFIG_DO_TESTS
	/* Execute ktests */
	do_ktests();
#endif

	/* Mount the root partition */
	char *root_partition = kernel_getopt("--root");
	if(!root_partition)
		panic("--root wasn't specified in the kernel arguments");

	/* Note that we don't actually allocate an extra byte for the NULL terminator, since the partition number will
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
		WARN("kernel", "root device not found!\n");

	/* Pass the root partition to init */
	char *args[] = {"", root_partition, NULL};
	char *envp[] = {"PATH=/bin:/usr/bin:/sbin:", NULL};

	assert(find_and_exec_init(args, envp) == 0);

	set_current_state(THREAD_BLOCKED);
	for (;;);
}
