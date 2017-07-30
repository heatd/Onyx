/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include <sys/ptrace.h>

void do_trace(pid_t pid)
{
	if(ptrace(PTRACE_ATTACH, pid) < 0)
	{
		perror("strace: ptrace");
		kill(pid, SIGKILL);
		exit(1);
	}
	printf("Tracing %d\n", pid);
	ptrace(PTRACE_CONT, pid);
	while(1);
}
void do_child(int argc, char **argv)
{
	raise(SIGSTOP);
	printf("Being traced!\n");
	if(execvp(argv[0], argv) < 0)
		exit(1);
}
void print_usage(char *prog)
{
	printf("%s - system call tracer\nUsage: %s [program] [args] ...\n", prog, prog);
}
int main(int argc, char **argv, char **envp)
{
	if(argc < 2)
	{
		print_usage(argv[0]);
		return 1;
	}
	pid_t pid = fork();
	if(pid < 0)
	{
		perror("strace");
		return 1;
	}
	else if(pid > 0)
	{
		do_trace(pid);
	}
	else
	{
		do_child(argc - 1, argv + 1);
	}
	return 0;
}
