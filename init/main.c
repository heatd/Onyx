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
#define write_log(x) write(STDOUT_FILENO, x, strlen(x))
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
int posix_spawn(char *path, void *d, void* w, char* argv, char *envp)
{
	int ret;
	asm volatile("int $0x80":"=a"(ret):"a"(9));
	return ret;
}
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
	/*char *exec = buf;
	size_t size = 0;
	while(*exec != ' '||*exec != '\n'||*exec!='\0')
	{
		size++;
	}
	char path[size];
	memcpy(path, exec, size);*/
	return 1;

}
int help(char *unused)
{
	write_log("Commands: uname\n\t  help\n\t  echo\n\t  whoami\n\t  getshellpid\n");
}
int uname(char *unused)
{
	write_log("Spartix 0.1-rc3 x86_64\n");
}
int echo(char *str)
{
	write_log(str);
}
int whoami(char *unused)
{
	write_log("root\n");
}
int getshellpid(char *unused)
{
	char c = getpid() + 48;
	write(STDOUT_FILENO, &c, 1);
	write_log("\n");
}
int _start(int argc, char **argv, char **envp)
{
	write_log("/sbin/init invoked!\n");
	write_log("Becoming the shell!\n");
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
	write_log("/sbin/init $ ");
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
	int ret = process_command();
	if(ret)
	{
		write(STDOUT_FILENO, buf, pos - 1);
		write_log(" : Command not found!\n");
	}
	memset(buf, 0, 1024);
	pos = 0;
	goto loop;
	return 0;
}