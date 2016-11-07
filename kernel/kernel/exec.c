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
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <pthread_kernel.h>

#include <sys/mman.h>

#include <kernel/task_switching.h>
#include <kernel/elf.h>
#include <kernel/vfs.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <kernel/envp.h>
#include <kernel/compiler.h>

int exec(const char *path, char **argv, char **envp)
{
	process_t *proc = process_create(path, NULL, NULL);
	if(!proc)
		return errno = ENOMEM, -1;
	vfsnode_t *in = open_vfs(fs_root, path);
	if (!in)
	{
		printf("%s: %s\n", path, strerror(errno));
		return errno = ENOENT;
	}
	char *buffer = malloc(in->size);
	if (!buffer)
		return errno = ENOMEM;
	read_vfs(0, in->size, buffer, in);
	void *entry = elf_load((void *) buffer);
	char **env = copy_env_vars(envp);
	int argc;
	char **args = copy_argv(argv, path, &argc);
	extern PML4 *current_pml4;
	proc->cr3 = current_pml4;
	extern vmm_entry_t *areas;
	extern size_t num_areas;
	proc->areas = areas;
	proc->num_areas = num_areas;
	proc->brk = vmm_allocate_virt_address(0, 1, VMM_TYPE_REGULAR, VMM_USER|VMM_WRITE);
	if(!proc->brk)
		return errno = ENOMEM;
	vmm_map_range(proc->brk, 1, VMM_WRITE | VMM_USER);
	// Allocate space for %fs TODO: Do this while in elf_load, as we need the TLS size
	uintptr_t *fs = vmm_allocate_virt_address(0, 1, VMM_TYPE_REGULAR, VMM_WRITE | VMM_NOEXEC | VMM_USER);
	vmm_map_range(fs, 1, VMM_WRITE | VMM_NOEXEC | VMM_USER);
	pthread_t *p = (struct pthread*) fs;
	p->self = (pthread_t*) fs;
	proc->fs = (uintptr_t) fs;
	asm volatile("cli");
	process_create_thread(proc, (ThreadCallback) entry, 0, argc, args, env);
	p->tid = proc->threads[0]->id;
	p->pid = proc->pid;
	free(buffer);
	free(in);
	asm volatile("sti");
	return 0;
}
