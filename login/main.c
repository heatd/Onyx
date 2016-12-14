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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

void switch_users()
{
	uid_t uid = 0;
	gid_t gid = 0;
	setuid(uid);
	setgid(gid);
}
/* TODO: Construct the envp properly */
char **args;
int main(int argc, char **argv, char **envp)
{
	args = argv;
	printf("%s: ", argv[0]);
	char *buf = malloc(1024);
loop:
	printf("username:");
	if(!buf)
		return 1;
	fgets(buf, 1024, stdin);
	if(strcmp(buf, "root") != 0)
	{
		printf("Unknown username %s!\n", buf);
		goto loop;
	}
	printf("password:");
	fgets(buf, 1024, stdin);
	if(strcmp(buf, "root") != 0)
	{
		printf("Unknown password! Try again.\n", buf);
		goto loop;
	}
	switch_users();
	/* Spawn the login shell */
	int pid = fork();
	if(pid == 0)
	{
		extern char **environ;
		execve("/bin/sh", args, environ);
	}
	while(1);
	return 0;
}
