/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>

extern void _init();
extern int main(int argc, char **argv, char **envp, void *auxv);
int _dlstart(int argc, char **argv, char **envp, void *auxv)
{
	/* Call the global constructors */
	_init();
	/* Call main and exit */
	exit(main(argc, argv, envp, auxv));
	return 0;
}