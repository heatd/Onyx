/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
char *prog = NULL;
void print_usage(void)
{
	printf("Usage: %s - Print every environment variable in the environment\n", prog);
	printf("\t--help: Output this help message and exit\n\t--version: Output the version information and exit\n");
}
void print_version(void)
{
	printf("%s 0.1 - Onyx utilities\n", prog);
}
void parse_args(int argc, char * const *argv)
{
	int opt;
	while((opt = getopt(argc, argv, "v")) > 0)
	{
		switch(opt)
		{
			case '?':
				print_usage();
				exit(EXIT_FAILURE);
			case 'v':
				print_version();
				exit(EXIT_SUCCESS);
		}
	}
}
int main(int argc, char **argv, char **envp)
{
	parse_args(argc, argv);
	prog = argv[0];
	while(*envp)
		printf("%s\n", *envp++);
	return 0;
}
