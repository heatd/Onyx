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
#include <stdlib.h>

extern void _init();
extern int main(int argc, char **argv, char **envp);
int _dlstart(int argc, char **argv, char **envp)
{
	/* Call the global constructors */
	_init();
	/* Call main and exit */
	exit(main(argc, argv, envp));
	return 0;
}