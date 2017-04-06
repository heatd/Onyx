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
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <errno.h>
int main(int argc, char **argv)
{
	for(int i = 0; i < argc; i++)
	{
		printf("Arg: %s\n", argv[i]);
	}
	struct stat buf;
	int r = stat("/sbin/init", &buf);
	printf("stat() returned %d\n", r);
	printf("Size: %x\n", buf.st_size);
	printf("Errno: %d\n", errno);
	return 0;
}