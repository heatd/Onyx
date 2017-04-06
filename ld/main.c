/*----------------------------------------------------------------------
 * Copyright (C) 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>

#include <sys/stat.h>

/* Utility function to read a whole file to a buffer - returns NULL on any failure */
void *read_file(const char *path)
{
	/* Get the size of the file */
	struct stat buf;
	memset(&buf, 0, sizeof(struct stat));
	if(stat(path, &buf) < 0)
		return NULL;
	size_t file_size = buf.st_size;
	printf("File\n");
	/* Allocate a buffer with the apropriate size */
	void *buffer = malloc(file_size);
	if(!buffer)
		return NULL;

	/* Open the file and read it */
	FILE *fp = fopen(path, "r");
	if(!fp)
	{
		free(buffer);
		return NULL;
	}

	if(fread(buffer, file_size, 1, fp) != file_size)
	{
		/* If it failed to read it, free the buffers, close the file and return a failure */
		free(buffer);
		fclose(fp);
		return NULL;
	}

	return buffer;
}
/* Check if it's a valid elf64 x86_64 SYSV ABI file */
int verify_elf(void *file)
{
	Elf64_Ehdr *header = (Elf64_Ehdr *) file;
	if (header->e_ident[EI_MAG0] != ELFMAG0 || header->e_ident[EI_MAG1] != ELFMAG1 
		|| header->e_ident[EI_MAG2] != ELFMAG2 || header->e_ident[EI_MAG3] != ELFMAG3)
		return 1;
	if (header->e_ident[EI_CLASS] != ELFCLASS64)
		return 1;
	if (header->e_ident[EI_DATA] != ELFDATA2LSB)
		return 1;
	if (header->e_ident[EI_VERSION] != EV_CURRENT)
		return 1;
	if (header->e_ident[EI_OSABI] != ELFOSABI_SYSV)
		return 1;
	if (header->e_ident[EI_ABIVERSION] != 0)	/* SYSV specific */
		return 1;
	return 0;
}
int load_prog(const char *filename)
{
	/* Read the file */
	void *file = read_file(filename);
	if(!file)
		return 1;

	/* and check if it's valid */
	if(verify_elf(file) < 0)
	{
		free(file);
		return 1;
	}
	printf("%s is a valid elf file!\n", filename);
}
int main(int argc, char **argv)
{
	/* In our case, argv[0] is the to-be-loaded program's name*/
	return load_prog((const char *) argv[0]);
}