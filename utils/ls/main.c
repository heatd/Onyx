/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/stat.h>

static int all = 0;
static int recursive = 0;
void parse_args(int argc, char * const *argv)
{
	int opt = 0;
	while((opt = getopt(argc, argv, "aAR")) > 0)
	{
		switch(opt)
		{
			case 'a':
				all = 1;
				break;
			case 'A':
			{
				if(!all)
					all = 2;
				break;
			}
			case 'R':
				recursive = 1;
				break;
		}
	}
}
int do_ls(char *filename)
{
	DIR *dirct = opendir(filename);
	if(!dirct)
		return 1;
	struct dirent *dir = NULL;
	while((dir = readdir(dirct)))
	{
		if(strncmp(dir->d_name, ".", 1) == 0)
		{
			if(!all)
				continue;
			else if(all == 2)
			{
				if(dir->d_name[0] == '.' && strlen(dir->d_name) == 1)
					continue;
				if(dir->d_name[1] == '.' && strlen(dir->d_name) == 2)
					continue;
			}
		}
		printf("%s ", dir->d_name);
		switch(dir->d_type)
		{
			case DT_UNKNOWN:
			{
				//printf("unknown\n");
				break;
			}
			case DT_REG:
			{
				//printf("regular file\n");
				break;
			}
			case DT_FIFO:
			{
				//printf("named pipe\n");
				break;
			}
			case DT_BLK:
			{
				//printf("block device\n");
				break;
			}
			case DT_CHR:
			{
				//printf("character device\n");
				break;
			}
			case DT_DIR:
			{
				//printf("directory\n");
				if(recursive && dir->d_name[0] != '.')
				{
					size_t buf_size = strlen(filename) + strlen(dir->d_name) + 2;
					char *full_path = malloc(buf_size);
					if(!full_path)
						abort();
					memset(full_path, 0, buf_size);
					strcpy(full_path, filename);
					if(full_path[strlen(full_path)] != '/')
						full_path[strlen(full_path)] = '/';
					strcat(full_path, dir->d_name);
					int ret = 0;
					if((ret = do_ls(full_path)))
					{
						free(full_path);
						return ret;
					}
					free(full_path);
				}
				break;
			}
			case DT_LNK:
			{
				//printf("symlink\n");
				break;
			}
			case DT_SOCK:
			{
				//printf("unix socket\n");
				break;
			}
		}
	}
	printf("\n");
	closedir(dirct);
	return 0;
}
int main(int argc, char **argv)
{
	parse_args(argc, argv);
	if(argc < 2)
		return 1;
	return do_ls(argv[argc-1]);
}
