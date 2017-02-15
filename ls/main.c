/*----------------------------------------------------------------------
 * Copyright (C) 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/stat.h>
int main(int argc, char **argv)
{
	if(argc < 2)
		return 1;
	DIR *dirct = opendir(argv[1]);
	if(!dirct)
		return 1;
	struct dirent *dir = NULL;

	while((dir = readdir(dirct)))
	{
		printf("%u %s - ", dir->d_ino, dir->d_name);
		switch(dir->d_type)
		{
			case DT_UNKNOWN:
			{
				printf("unknown\n");
				break;
			}
			case DT_REG:
			{
				printf("regular file\n");
				break;
			}
			case DT_FIFO:
			{
				printf("named pipe\n");
				break;
			}
			case DT_BLK:
			{
				printf("block device\n");
				break;
			}
			case DT_CHR:
			{
				printf("character device\n");
				break;
			}
			case DT_DIR:
			{
				printf("directory\n");
				break;
			}
			case DT_LNK:
			{
				printf("symlink\n");
				break;
			}
			case DT_SOCK:
			{
				printf("unix socket\n");
				break;
			}
		}
	}
	return 0;
}