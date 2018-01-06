/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <string.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
	if(argc > 1)
		printf("%s\n", argv[1]);
	else
		printf("%s: Usage: %s [arguments]\n", argv[0], argv[0]);
	return 0;
}
