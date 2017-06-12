/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <string.h>
void print_usage()
{
	printf("Usage: yes [STRING]\nor yes OPTION\nRepeatedly output a string, or yes by default.\n");
	printf("\t--help: Output this help message and exit\n\t--version: Output the version information and exit\n");
	exit(0);
}
void print_version()
{
	printf("yes - Onyx utils 0.4\n");
	exit(0);
}
int main(int argc, char **argv)
{
	char *string = "y";
	if(argc > 1)
	{
		if(!strcmp(argv[1], "--help"))
			print_usage();
		else if(!strcmp(argv[1], "--version"))
			print_version();
		else
			string = argv[1];
		return 0;
	}
	while(1)
		printf("%s\n", string);
	return 0;
}
