/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include "internal.h"
#include <fcntl.h>
#include <sys/stat.h>

Unwind_info *do_raw_unwind(uintptr_t *frame, size_t *size, elf_object_t *elf)
{
	Unwind_info *buffer = NULL;
	size_t sz = 0;
	/* Now, lets go through the linked list of stack frames */
	while(*frame)
	{
		if(!(void*)*(frame+1))
			break;
		/* now we'll get the return address */
		uintptr_t address = *(frame+1);
		buffer = realloc(buffer, ++sz * sizeof(Unwind_info));
		if(!buffer)
			return buffer;
		buffer[sz-1].address = address;
		/* Go through the symbol names, and get the symbol name */
		buffer[sz-1].name = resolve_sym(address, elf);
		frame = (uintptr_t*) *frame;
	}
	*size = sz;
	return buffer;
}

Unwind_info *Unwind_stack(size_t *size)
{
	/* TODO: This doesn't work if argv[0] is a relative path and the program changed 
	the working directory. Instead, we should try add something like /proc/self/exe */
	char *path = program_invocation_name;
	/* The program state might be chaos, we don't want to invoke too much malloc */

	/* Open the program */
	int fd = open(path, O_RDONLY);
	if(fd < 0)	
		return NULL;
	/* Get the program's size */
	struct stat buf;
	if(fstat(fd, &buf) < 0)
	{
		close(fd);
		return NULL;
	}
	/* Allocate a buffer for the program binary */
	void *buffer = malloc(buf.st_size);
	if(!buffer)
	{
		close(fd);
		return NULL;
	}

	read(fd, buffer, buf.st_size);

	/* TODO: Handle symbols from multiple binaries(so libc.so, libdrm.so, etc can be easily debugged) */
	elf_object_t *elf = elf_parse(buffer);
	if(!elf)
	{
		free(buffer);
		close(fd);
		return NULL;
	}
	/* We want Unwind_unwind's return address */
	uintptr_t *frame = __builtin_frame_address(1); 
	return do_raw_unwind(frame, size, elf);
}
