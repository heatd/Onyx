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

__attribute__((noreturn))
void _exit(int code)
{
	syscall(SYS_exit, code);
	__builtin_unreachable();
}
pid_t fork()
{
	syscall(SYS_fork);
	return rax;
}
pid_t getpid()
{
	syscall(SYS_getpid);
	return rax;
}
pid_t getppid()
{
	syscall(SYS_getppid);
	return rax;
}
