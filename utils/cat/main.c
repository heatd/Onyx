/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
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
	{
		fclose(file);
		return 1;
	}
	size_t file_size = ftell(file);
	rewind(file);
	char *buf = malloc(file_size);
	if(!buf)
	{
		fclose(file);
		return 1;
	}
	fread(buf, file_size, 1, file);
	printf("%s", buf);
	fclose(file);
	free(buf);
	return 0;
}
