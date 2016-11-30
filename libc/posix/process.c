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
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdio.h>
__attribute__((noreturn))
void _exit(int code)
{
	syscall(SYS_exit, code);
	__builtin_unreachable();
}
pid_t fork()
{
	syscall(SYS_fork);
	if(rax == (unsigned long long) -1)
	{
		set_errno();
	}
	return rax;
}
pid_t getpid()
{
	syscall(SYS_getpid);
	if(rax == (unsigned long long) -1)
	{
		set_errno();
	}
	return rax;
}
pid_t getppid()
{
	syscall(SYS_getppid);
	if(rax == (unsigned long long) -1)
	{
		set_errno();
	}
	return rax;
}
int execve(const char *filename, char *const argv[], char *const envp[])
{
	syscall(SYS_execve, filename, argv, envp);
	set_errno();
	return rax;
}
int posix_spawn(pid_t *pid, const char *path, const void *file_actions
, const void *attrp, char *const argv[], char *const envp[])
{
	(void) pid;
	(void) path;
	(void) file_actions;
	(void) attrp;
	(void) argv;
	(void) envp;
	asm volatile("mov %0, %%rax; int $0x80"::"i"(SYS_posix_spawn));
	return 0;
}
int setuid(uid_t uid)
{
	syscall(SYS_setuid, uid);
	if(rax == (unsigned long long) -1)
	{
		set_errno();
	}
	return rax;
}
int setgid(gid_t gid)
{
	syscall(SYS_setgid, gid);
	if(rax == (unsigned long long) -1)
	{
		set_errno();
	}
	return rax;
}
