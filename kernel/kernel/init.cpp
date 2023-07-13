/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
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

#include <assert.h>
#include <errno.h>
#include <multiboot2.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include <onyx/acpi.h>
#include <onyx/binfmt.h>
#include <onyx/block.h>
#include <onyx/bootmem.h>
#include <onyx/clock.h>
#include <onyx/cmdline.h>
#include <onyx/cpu.h>
#include <onyx/crypt/sha256.h>
#include <onyx/debug.h>
#include <onyx/dev.h>
#include <onyx/driver.h>
#include <onyx/elf.h>
#include <onyx/exec.h>
#include <onyx/heap.h>
#include <onyx/init.h>
#include <onyx/initrd.h>
#include <onyx/irq.h>
#include <onyx/ktrace.h>
#include <onyx/log.h>
#include <onyx/modules.h>
#include <onyx/page.h>
#include <onyx/pagecache.h>
#include <onyx/paging.h>
#include <onyx/panic.h>
#include <onyx/percpu.h>
#include <onyx/power_management.h>
#include <onyx/process.h>
#include <onyx/random.h>
#include <onyx/rwlock.h>
#include <onyx/sysfs.h>
#include <onyx/task_switching.h>
#include <onyx/timer.h>
#include <onyx/tss.h>
#include <onyx/tty.h>
#include <onyx/utils.h>
#include <onyx/vdso.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>
#include <onyx/worker.h>

#include <acpica/acpi.h>
#include <pci/pci.h>
#include <uapi/fcntl.h>

#include <onyx/linker_section.hpp>

void *initrd_addr = nullptr;
size_t initrd_length = 0;

void set_initrd_address(void *initrd_address, size_t length)
{
    initrd_addr = initrd_address;
    initrd_length = length;
}

int sys_execve(const char *p, const char **argv, const char **envp);

int find_and_exec_init(const char **argv, const char **envp)
{
    struct process *proc = process_create("kernel", nullptr, nullptr);
    if (!proc)
        return -ENOMEM;

    vm_save_current_mmu(proc->address_space.get());
    if (vm_create_address_space(proc->address_space.get()) < 0)
    {
        return -ENOMEM;
    }

    proc->address_space->page_tables_size = PAGE_SIZE;

    struct thread *current_thread = get_current_thread();
    current_thread->owner = proc;
    sched_transition_to_user_thread(current_thread);

    process_add_thread(proc, current_thread);

    // TODO: Should we open some sort of logging device (akin to /dev/console) by default?
#if 0
	/* Setup standard file descriptors (STDIN(0), STDOUT(1), STDERR(2)) */
	
	unsigned int flags[3] = {O_RDONLY, O_WRONLY, O_WRONLY};

	for(int i = 0; i < 3; i++)
	{
		struct file *streams = open_vfs(get_fs_root(), "/dev/tty");
	
		assert(open_with_vnode(streams, flags[i]) == i);
		fd_put(streams);
	}
#endif
    proc->ctx.cwd = get_fs_root();
    fd_get(proc->ctx.cwd);

    const char *init_paths[] = {"/sbin/init", "/bin/init", "/bin/sh"};

    for (auto init_path : init_paths)
    {
        argv[0] = init_path;
        int st = sys_execve(init_path, argv, envp);

        if (st < 0)
        {
            /* Aww, it didn't work out */
            thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);
        }
    }

    return -1;
}

static thread_t *new_thread;

void kernel_multitasking(void *arg);
void reclaim_initrd();
void do_ktests();

struct init_level_info
{
    unsigned long *level_start;
    unsigned long *level_end;
};

DEFINE_LINKER_SECTION_SYMS(__init_level0_start, __init_level0_end);
DEFINE_LINKER_SECTION_SYMS(__init_level1_start, __init_level1_end);
DEFINE_LINKER_SECTION_SYMS(__init_level2_start, __init_level2_end);
DEFINE_LINKER_SECTION_SYMS(__init_level3_start, __init_level3_end);
DEFINE_LINKER_SECTION_SYMS(__init_level4_start, __init_level4_end);
DEFINE_LINKER_SECTION_SYMS(__init_level5_start, __init_level5_end);
DEFINE_LINKER_SECTION_SYMS(__init_level6_start, __init_level6_end);
DEFINE_LINKER_SECTION_SYMS(__init_level7_start, __init_level7_end);
DEFINE_LINKER_SECTION_SYMS(__init_level8_start, __init_level8_end);

static linker_section init_levels[INIT_LEVEL_CORE_PERCPU_CTOR + 1] = {
    {&__init_level0_start, &__init_level0_end}, {&__init_level1_start, &__init_level1_end},
    {&__init_level2_start, &__init_level2_end}, {&__init_level3_start, &__init_level3_end},
    {&__init_level4_start, &__init_level4_end}, {&__init_level5_start, &__init_level5_end},
    {&__init_level6_start, &__init_level6_end}, {&__init_level7_start, &__init_level7_end},
    {&__init_level8_start, &__init_level8_end}};

void do_init_level(unsigned int level)
{
    auto nr = init_levels[level].size() / sizeof(void *);
    auto func = init_levels[level].as<void (*)()>();
    for (size_t i = 0; i < nr; i++, func++)
    {
        (*func)();
    }
}

void do_init_level_percpu(unsigned int level, unsigned int cpu)
{
    auto nr = init_levels[level].size() / sizeof(void *);
    auto func = init_levels[level].as<void (*)(unsigned int)>();
    for (size_t i = 0; i < nr; i++, func++)
    {
        (*func)(cpu);
    }
}

void fs_init()
{
    /* Initialize the VFS */
    vfs_init();

    if (!initrd_addr)
        panic("Initrd not found");

    initrd_addr = (void *) ((char *) initrd_addr + PHYS_BASE);

    /* Initialize the initrd */
    init_initrd(initrd_addr, initrd_length);

    reclaim_initrd();
}

extern "C" void kernel_main(void)
{
    cmdline::init();
    do_init_level(INIT_LEVEL_VERY_EARLY_CORE);

    do_init_level(INIT_LEVEL_VERY_EARLY_PLATFORM);

    fs_init();

    do_init_level(INIT_LEVEL_EARLY_CORE_KERNEL);

    do_init_level(INIT_LEVEL_EARLY_PLATFORM);

    do_init_level(INIT_LEVEL_CORE_PLATFORM);

    do_init_level(INIT_LEVEL_CORE_INIT);

    irq_disable();

    /* Initialize the scheduler */
    if (sched_init())
        panic("sched: failed to initialize!");

    /* Initalize multitasking */
    new_thread = sched_create_thread(kernel_multitasking, 1, nullptr);

    assert(new_thread);

    /* Start the new thread */
    sched_start_thread(new_thread);

    irq_enable();

    sched_transition_to_idle();
}

void kernel_multitasking(void *arg)
{
#ifdef CONFIG_DO_TESTS
    /* Execute ktests */
    do_ktests();
#endif

    do_init_level(INIT_LEVEL_CORE_AFTER_SCHED);

    do_init_level(INIT_LEVEL_CORE_KERNEL);

    /* Start populating /dev */
    entropy_init_dev(); /* /dev/random and /dev/urandom */

    /* Mount sysfs */
    sysfs_mount();

    /* Populate /sys */
    vm_sysfs_init();

    // XXX HACK
    auto roots = cmdline::get_root();

    if (roots.empty())
        roots = {"/dev/dummy0"};
    /* Pass the root partition to init */
    auto root = cul::string(roots);
    if (!root)
        panic("out of memory in early boot");
    const char *args[] = {(char *) "", root.c_str(), nullptr};
    const char *envp[] = {"PATH=/bin:/usr/bin:/sbin:", "TERM=linux", "LANG=C", "PWD=/", nullptr};

    if (find_and_exec_init(args, envp) < 0)
    {
        panic("Failed to exec init!");
    }
}
