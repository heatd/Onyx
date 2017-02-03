/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/utsname.h>

#include <drm/drm.h>
/* x is a placeholder */
char *prefix = "/etc/init.d/rcx.d";
int tonum(int c)
{
	return c - '0';
}
int isnum(int c)
{
	if(c >= 48 && c <= 57)
		return 1;
	return 0;
}
char *copy_until_newline(char *s)
{
	char *str = s;
	size_t len = 0;
	while(*str != '\n' && *str != '\0')
	{
		len++;
		str++;
	}
	char *buffer = malloc(len + 1);
	memset(buffer, 0, len + 1);
	char *ret = buffer;
	str = s;
	for(; len; len--)
		*buffer++ = *str++;
	return ret;
		
}
void insmod(const char *path, const char *name)
{
	syscall(SYS_insmod, path, name);
}
int main(int argc, char **argv, char **envp)
{
	printf("/sbin/init invoked!\n");
	/* Open the config */
	FILE *f = fopen("/etc/init.d/init.config", "rw");
	if(!f)
	{
		perror("/etc/init.d/init.config");
		return 1;
	}
	char *buf = malloc(1024);
	if(!buf)
	{
		perror("/sbin/init");
		return 1;
	}
	memset(buf, 0, 1024);
	int ringlevel = 0;
	/* Now lets loop through the file, and get the default ring level */
	fread(buf, 1024, 1, f);
	if(memcmp(buf, "defaultrl:", strlen("defaultrl:")) == 0)
	{
		/* If the argument after 'defaultrl:' isn't a number, throw a parsing error and return 1*/
		if(!isnum(*(buf + strlen("defaultrl:"))))
		{
			printf("syntax error: at '%c'\n", *(buf + strlen("defaultrl:")));
			return 1;
		}
		else
		{
			/* It's a number, use tonum(3), as ring levels are from 0-6 */
			ringlevel = tonum(*(buf + strlen("defaultrl:")));
			//printf("Ring level: %d\n", ringlevel);
		}
	}
	/* Free up the resources we've just used */
	fclose(f);
	/* Allocate a buffer for the filename */
	char *filename = malloc(strlen(prefix) + 4);
	if(!filename)
		return 1;
	strcpy(filename, prefix);
	/*  Edit in the ring level */
	filename[14] = ringlevel + '0';
	/* Open the script file */
	f = fopen(filename, "r");
	if(!f)
	{
		printf("%s: No such file or directory!\n", filename);
		return 1;
	}
	memset(buf, 0, 1024);
	fgets(buf, 1024, f);
	char *env[] = {"", NULL};
	char *shell = copy_until_newline(buf);
	char *args[] = {shell, "/etc/fstab", NULL};

	printf("Shell: %s\n", shell);
	
	sethostname("localhost", strlen("localhost"));
	
	void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANON,
                  0, 0);
	
	uname((char*) addr + 4095);
	insmod("/lib/modules/ahci.kmod", "ahci");
	insmod("/lib/modules/drm.kmod", "drm");

	fflush(stdout);
	struct drm_info *info = NULL;
	if(drm_initialize(&info) < 0)
		printf("Error: Failed to initialize drm!\n");
	char *log = malloc(4096);
	syscall(46, 2, log, 4096);
	printf(log);
	int pid = fork();
	
	if(pid == 0)
		execve(shell, args, env);
	while(1);
	return 0;
}
