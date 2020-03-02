/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

void print_usage(char *prog_name)
{
	printf("%s: Usage: %s [FILE]...\n", prog_name, prog_name);
}

const char *noargs_args[] = {"-", NULL};

#define BUF_SIZE			4096

int do_cat(const char **args)
{
	char *buf = malloc(BUF_SIZE);
	if(!buf)
	{
		perror("cat");
		return 1;
	}

	memset(buf, 0, BUF_SIZE);
	const char **argp = args;

	while(*argp)
	{
		const char *arg = *argp;
		
		int fd;

		if(arg[0] == '-')
		{
			if(arg[1] != '\0')
			{
				/* This is an argument, ignore */
				argp++;
				continue;
			}

			fd = STDIN_FILENO;
		}
		else
		{
			fd = open(arg, O_RDONLY);
			if(fd < 0)
			{
				perror("cat");
				return 1;
			}
		}

		ssize_t nread = 0;
		while((nread = read(fd, buf, BUF_SIZE)) != 0)
		{
			if(nread < 0)
			{
				perror("cat: read");
				return 1;
			}

			if(write(STDOUT_FILENO, buf, nread) < 0)
			{
				perror("cat: write");
				return 1;
			}
		}

		argp++;

		if(fd != STDIN_FILENO)
			close(fd);
	}
}

int main(int argc, char **argv, char **envp)
{
	/* TODO: Parse args */
	if(argc < 2)
	{
		return do_cat(noargs_args);
	}

	return do_cat((const char **) (argv + 1));
}
