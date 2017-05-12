/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdio.h>
#pragma GCC push_options
#pragma GCC diagnostic ignored "-Wunused-parameter"
__attribute__((noreturn))
void _exit(int code)
{
	__builtin_unreachable();
}
pid_t fork()
{
	return 0;
}
pid_t getpid()
{
	return 0;
}
pid_t getppid()
{
	return 0;
}
int execve(const char *filename, char *const argv[], char *const envp[])
{
	return 0;
}
int posix_spawn(pid_t *pid, const char *path, const void *file_actions
, const void *attrp, char *const argv[], char *const envp[])
{
	return 0;
}
int setuid(uid_t uid)
{
	return 0;
}
int setgid(gid_t gid)
{
	return 0;
}
#pragma GCC pop_options
