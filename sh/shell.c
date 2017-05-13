/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

/* Counts the number of chars until a space or newline or \0 */
size_t strslength(char *string)
{
	size_t __strlen = 0;
	while(*string)
	{
		if(*string == '\n')
			return __strlen;
		if(*string == ' ')
			return __strlen;
		++__strlen;
		*string++;
	}
	return __strlen;
}
void *memdup(void *ptr, size_t size)
{
	void *new_ptr = malloc(size);
	if(!new_ptr)
		return NULL;
	memcpy(new_ptr, ptr, size);
	return new_ptr;
}
char **get_args(char *args, char *prog_name, int *argc)
{
	char **argv;
	char *saveptr;
	size_t nr_args = 0;
	argv = NULL;
	saveptr = NULL;
	argv = malloc(sizeof(char*));
	nr_args++;
	argv[0] = strdup(prog_name);
	args = strtok_r(args, " ", &saveptr);
	while(args)
	{
		++nr_args;
		argv = realloc(argv, nr_args * sizeof(char*));
		if(!argv)
		{
			perror("get_args:");
			if(argv)
				free(argv);
			return NULL;
		}
		argv[nr_args-1] = strdup(args);
		args = strtok_r(NULL, " ", &saveptr);
	}

	/* Argv needs to be NULL terminated */
	nr_args++;
	argv = realloc(argv, nr_args * sizeof(char*));
	if(!argv)
	{
		perror("get_args:");
		if(argv)
			free(argv);
		return NULL;
	}
	argv[nr_args-1] = NULL;
	*argc = nr_args-1;
	return argv;
}
int run_command(char *command)
{
	/* Get the program's name */
	size_t prog_name_size = strslength(command);
	char *program_name = memdup(command, prog_name_size);
	program_name[prog_name_size] = '\0';

	/* Get the start of the arguments */
	char *args = command + prog_name_size + 1;
	
	int argc;
	char **argv = get_args(args, program_name, &argc);

	int pid = fork();
	if(pid < 0)
	{
		perror("run_command:");
		return -1;
	}
	else if(pid == 0)
	{
		if(execv(argv[0], argv) < 0)
		{
			exit(127);
		}
	}
	while(1);
	return 0;
}