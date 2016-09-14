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
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
char buf[1024] = {0};
volatile size_t pos = 0;
#define MAX_COMMANDS 100
int last_command_index = 0;
typedef int(*command_callback_t)(char *args);
typedef struct
{
	const char *name;
	command_callback_t cmdc;
} command_t;
command_t commands[MAX_COMMANDS];
int process_command()
{
	for(int i = 0; i < last_command_index; i++)
	{
		if(memcmp(buf, commands[i].name,strlen(commands[i].name)) == 0)
		{
			command_callback_t call = commands[i].cmdc;
			call(&buf[strlen(commands[i].name)]);
			return 0;
		}
	}
	pid_t pid = fork();
	if(pid == 0)
	{
		if(execve(buf, NULL, environ))
			exit(1);
	}
	if(pid > 0)
	{
		int status;
		wait(&status);
		return 0;
	}
	return 1;
}
int help(char *unused)
{
	printf("Commands: uname\n\t  help\n\t  echo\n\t  whoami\n\t  getshellpid\n");
}
int uname(char *unused)
{
	printf("Spartix 0.2-dev x86_64\n");
}
int echo(char *str)
{
	printf("%s\n",str);
}
int whoami(char *unused)
{
	printf("root\n");
}
int getshellpid(char *unused)
{
	printf("pid: %d\n", getpid());
}
int _start(int argc, char **argv, char **envp)
{
	printf("/sbin/init invoked!\n");
	printf("Becoming the shell!\n");
	commands[0].name = "help";
	commands[0].cmdc = help;
	last_command_index++;
	commands[1].name = "uname";
	commands[1].cmdc = uname;
	last_command_index++;
	commands[2].name = "echo";
	commands[2].cmdc = echo;
	last_command_index++;
	commands[3].name = "whoami";
	commands[3].cmdc = whoami;
	last_command_index++;
	commands[4].name = "getshellpid";
	commands[4].cmdc = getshellpid;
	last_command_index++;
loop:
	write(STDOUT_FILENO, "/sbin/init $ ", strlen("/sbin/init $ "));
	while(buf[pos-1] != '\n' && pos < 1024)
	{
		read(STDIN_FILENO, &buf[pos], 1);
		if(buf[pos] == '\b')
		{
			if(pos == 0)
				continue;
			write(STDOUT_FILENO, "\b", strlen("\b"));
			buf[pos] = 0;
			pos--;
			buf[pos] = 0;
		}
		else
		{
			write(STDOUT_FILENO, &buf[pos], 1);
			pos++;
		}
	}
	buf[pos-1] = '\0';
	int ret = process_command();
	if(ret)
	{
		if(buf[0] == '\n')
		{
			buf[0] = 0;
			pos = 0;
			goto loop;
		}
		printf("%s : Command not found!\n", buf);
	}
	memset(buf, 0, 1024);
	pos = 0;
	goto loop;
	return 0;
}