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
#include <stdlib.h>
#include <string.h>

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
	/* Allocate a buffer with the apropriate size */
	void *buffer = malloc(file_size);
	if(!buffer)
		return NULL;

	/* Open the file and read it */
	FILE *fp = fopen(path, "rb");
	if(!fp)
	{
		free(buffer);
		return NULL;
	}
	size_t read = fread(buffer, 1, file_size, fp);
	if(read != file_size)
	{
		printf("read_file: read I/O error\n");
		fclose(fp);
		free(buffer);
		return NULL;
	}
	fclose(fp);
	return buffer;
}