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
#define PROG_VERSION "0.1"
#include <stdio.h>

int main(int argc, char **argv)
{
	printf("%s version %s\n", argv[0], PROG_VERSION);
	return 0;
}