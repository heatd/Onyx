/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <kernel/envp.h>
#include <kernel/vmm.h>

char **copy_env_vars(char **envp)
{
	if(!envp)
		return envp;
	size_t num_vars = 0;
	size_t total_size = 0;
	char **n = envp;
	while(*n != NULL)
	{
		num_vars++;
		total_size += strlen(*envp) + 1;
		total_size += sizeof(uintptr_t);
		n++;
	}
	size_t pages = total_size / PAGE_SIZE;
	if(total_size % PAGE_SIZE)
		pages++;
	uintptr_t *variables = vmm_allocate_virt_address(0, pages, VMM_TYPE_REGULAR, VMM_NOEXEC | VMM_WRITE | VMM_USER, 0);
	vmm_map_range(variables, pages,  VMM_NOEXEC | VMM_WRITE | VMM_USER);

	char *variable_strings = (char*)variables + num_vars * sizeof(uintptr_t);
	for(size_t i = 0; i < num_vars; i++)
	{
		variables[i] = (uint64_t)variable_strings;
		strcpy(variable_strings, envp[i]);
		variable_strings += strlen(envp[i]) + 1;
	}
	variables[num_vars] = 0;
	return (char **) variables;
}
char **copy_argv(char **argv, const char *path, int *argc)
{
	size_t num_args = 1;
	size_t total_size = sizeof(void*);
	char **n = argv;
	while(*n != NULL)
	{
		num_args++;
		total_size += strlen(*argv) + 1;
		total_size += sizeof(uintptr_t);
		n++;
	}
	size_t pages = total_size / PAGE_SIZE;
	if(total_size % PAGE_SIZE)
		pages++;
	uintptr_t *arguments = vmm_allocate_virt_address(0, pages, VMM_TYPE_REGULAR, VMM_NOEXEC | VMM_WRITE | VMM_USER, 0);
	vmm_map_range(arguments, pages,  VMM_NOEXEC | VMM_WRITE | VMM_USER);
	memset(arguments, 0, PAGE_SIZE * pages);
	char *argument_strings = (char*)arguments + num_args * sizeof(uintptr_t);
	for(size_t i = 0; i < num_args-1; i++)
	{	
		arguments[i] = (uint64_t)argument_strings;
		strcpy(argument_strings, argv[i]);
		argument_strings += strlen(argv[i]) + 1;
	}
	memset((char*)arguments + total_size, 0, total_size % PAGE_SIZE);
	*argc = num_args-1;
	return (char**) arguments;
}
