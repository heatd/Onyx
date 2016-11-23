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
	if(argc > 1)
		printf("%s\n", argv[1]);
	else
		printf("%s: Usage: %s [arguments]\n", argv[0], argv[0]);
	return 0;
}
