/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void print_usage(char *prog_name)
{
	printf("%s: Usage: %s [filename]\n", prog_name, prog_name);
}
int main(int argc, char **argv, char **envp)
{
	if(argc < 2)
	{
		print_usage(argv[0]);
		return 1;
	}
	FILE *file = fopen(argv[1], "r");
	if(!file)
	{
		perror(argv[1]);
		return 1;
	}
	if(fseek(file, 0L, SEEK_END) == -1)
		return 1;
	size_t file_size = ftell(file);
	rewind(file);
	char *buf = malloc(file_size);
	if(!buf)
		return 1;
	fread(buf, file_size, 1, file);
	printf("%s", buf);
	return 0;
}
