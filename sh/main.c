/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <time.h>

#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/syscall.h>

#define DEFAULT_PS1	"sh $ "

static char command_buffer[4096];

void print_current_ps1(void)
{
	char *ps1 = getenv("PS1");
	if(!ps1)
	{
		setenv("PS1", DEFAULT_PS1, 0);
	}
print:
	printf("%s", DEFAULT_PS1);
	fflush(stdout);
}
char *wait_for_command(void)
{
	fgets(command_buffer, 4096, stdin);
	char *pos;
	if((pos = strchr(command_buffer, '\n')))
    		*pos = '\0';
	return command_buffer;
}
#define SET_RETURN(retcode) ret = retcode
int handle_builtin_commands(char *command)
{
	int ret = 127;
	if(!strncmp(command, "echo", strlen("echo")))
	{
		command += strlen("echo");
		while(isspace(*command))
			++command;
		printf("%s\n", command);
		return 0;
	}
	else if(!strncmp(command, "uname", strlen("uname")))
	{
		struct utsname buf;
		uname(&buf);
		printf("%s %s %s %s %s %s\n", buf.sysname, buf.release, buf.version, buf.machine, buf.nodename, buf.__domainname);
		return 0;
	}
	else if(!strncmp(command, "date", strlen("date")))
	{
		struct timeval buf;
		syscall(SYS_gettimeofday, &buf, NULL);
		printf("%u\n", buf.tv_sec);
		return 0;
	}
	else if(!strncmp(command, "cat", strlen("cat")))
	{
		command += strlen("cat");
		while(isspace(*command))
			++command;
		FILE *fp = fopen(command, "r");
		if(!fp)
			return 127;
		char *buf = malloc(512);
		while(fgets(buf, 512, fp) != NULL)
		{
			printf("%s", buf);
		}
		puts("");
		free(buf);
		fclose(fp);
		return 0;
	}
	return 127;
}
extern char **environ;
void parse_command(char *command)
{
	int status = handle_builtin_commands(command);
	if(status == 0) /* If it was a builtin command, return */
		return;
	
	printf("sh: Command not found\n");
	goto end;
	/* FIX: Doesn't work yet */
	char *args = command;
	while(!isspace(*args))
		args++;
	char *argv[] = {command, args, NULL};
	int pid = fork();

	if(pid == 0)
		execvpe(command, argv, environ);
	while(1);
end:
	memset(command, 0, strlen(command));
}
int main(int argc, char **argv)
{
	int pid = fork();

	char *args[] = {"/bin/lua", NULL};
	if(pid == 0)
		execvpe("/bin/lua", args, environ);
	while(1)
	{
		/* Print the shell's PS1 */
		print_current_ps1();

		char *command = wait_for_command();

		parse_command(command);
	}
	return 0;
}
