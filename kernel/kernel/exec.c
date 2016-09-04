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
#include <kernel/task_switching.h>
#include <kernel/elf.h>
#include <kernel/vfs.h>
#include <kernel/panic.h>
#include <kernel/process.h>
int exec(const char *path, char **args)
{
	process_t *proc = process_create(path, NULL, NULL);
	vfsnode_t *in = open_vfs(fs_root, path);
	if (!in)
	{
		printf("%s: No such file or directory\n",path);
		return errno = ENOENT;
	}
	char *buffer = malloc(in->size);
	if (!buffer)
		return errno = ENOMEM;
	size_t read = read_vfs(0, in->size, buffer, in);
	if (read != in->size)
		return errno = EAGAIN;
	void *entry = elf_load((void *) buffer);
	size_t num_args = 1;
	size_t total_size = strlen(path) + 1 + sizeof(uintptr_t);
	char **n = args;
	while(*n != NULL)
	{
		num_args++;
		total_size += strlen(*args) + 1;
		total_size += sizeof(uintptr_t);
		n++;
	}
	size_t pages = total_size / PAGE_SIZE;
	if(total_size % PAGE_SIZE)
		pages++;
	uintptr_t *arguments = vmm_allocate_virt_address(0, pages, VMM_TYPE_REGULAR, VMM_NOEXEC | VMM_WRITE | VMM_USER);
	vmm_map_range(arguments, pages,  VMM_NOEXEC | VMM_WRITE | VMM_USER);
	char *argument_strings = (char*)arguments + num_args * sizeof(uintptr_t);
	for(size_t i = 0; i < num_args; i++)
	{
		if( i == 0)
		{
			arguments[i] = (uint64_t)argument_strings;
			strcpy(argument_strings, path);
			argument_strings += strlen(path) + 1;
			continue;
		}
		
		arguments[i] = (uint64_t)argument_strings;
		strcpy(argument_strings, args[i-1]);
		argument_strings += strlen(args[i-1]) + 1;
	}
	extern PML4 *current_pml4;
	proc->cr3 = current_pml4;
	extern vmm_entry_t *areas;
	extern size_t num_areas;
	proc->areas = areas;
	proc->num_areas = num_areas;
	process_create_thread(proc, (ThreadCallback) entry, 0, num_args, (char**)arguments);

	return 0;
}
