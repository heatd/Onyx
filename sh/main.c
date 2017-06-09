/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>
#include <err.h>
#include <errno.h>

#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/syscall.h>

#include <shell.h>
#include <login.h>

static char command_buffer[4096];
int run_command(char *command);

char *current_ps1 = "%s@%s %s %s ";
char *hostname = NULL;
char *current_dir[PATH_MAX];
uid_t uid = 0;
void print_current_ps1(void)
{
	printf(current_ps1, getenv("LOGNAME"), hostname, current_dir, uid == 0 ? "#" : "$");
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
		printf("%s", ctime(&buf.tv_sec));
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
	else if(!strncmp(command, "cd", strlen("cd")))
	{
		command += strlen("cd");
		while(isspace(*command))
			++command;
		if(chdir(command) < 0)
		{
			printf("cd: %s: %s\n", command, strerror(errno));
			return 1;
		}
		strcpy(current_dir, command);
		return 0;
	}
	return 127;
}
extern char **environ;
void parse_command(char *command)
{
	if(strlen(command) == 0)
		return;
	int status = handle_builtin_commands(command);
	if(status == 0) /* If it was a builtin command, return */
		return;
	else if(status == 127)
	{
		status = run_command(command);
	}
	if(status != -1)
		return;
	printf("sh: Command not found\n");
	goto end;

end:
	memset(command, 0, strlen(command));
}
int main(int argc, char **argv)
{
	if(argv[0][0] == '-')
		tash_do_login();
	hostname = malloc(HOST_NAME_MAX + 1);
	if(!hostname)
		err(1, "tash: out of memory\n");
	memset(hostname, 0, HOST_NAME_MAX + 1);
	gethostname(hostname, HOST_NAME_MAX + 1);

	getcwd(current_dir, PATH_MAX);
	uid = syscall(SYS_getuid);

	while(1)
	{
		/* Print the shell's PS1 */
		print_current_ps1();

		char *command = wait_for_command();

		parse_command(command);
	}
	return 0;
}
