/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#define PROG_VERSION "0.1"
#include <stdio.h>

int main(int argc, char **argv)
{
	printf("%s version %s\n", argv[0], PROG_VERSION);
	return 0;
}