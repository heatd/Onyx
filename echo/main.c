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
int _start(int argc, char **argv, char **envp)
{
	write(STDOUT_FILENO, "/bin/echo: usage: /bin/echo [arguments]\n", strlen("/bin/echo: usage: /bin/echo [arguments]\n"));
	exit(1);
	while(1);
	return 0;
}
