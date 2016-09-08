/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <unistd.h>
#include <string.h>
int main(int argc, char **argv, char **envp)
{
	write(STDOUT_FILENO, envp[0], strlen(envp[0]));
	if(argc > 1)
		write(STDOUT_FILENO, argv[1], strlen(argv[1]));
	else
	{
		write(STDOUT_FILENO, argv[0], strlen(argv[0]));
		write(STDOUT_FILENO, ": Usage: ", strlen(" Usage: "));
		write(STDOUT_FILENO, argv[0], strlen(argv[0]));
		write(STDOUT_FILENO, " [string]\n", strlen("[string]\n"));
		exit(1);
	}
	return 0;
}
