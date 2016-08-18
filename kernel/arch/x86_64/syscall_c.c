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
#include <stdint.h>
#include <unistd.h>
#include <kernel/tty.h>
#include <sys/types.h>
#include <kernel/process.h>
ssize_t sys_write(int fd, const void *buf, size_t count)
{
	if(fd == 1)
		tty_write(buf, count);

	return count;
}
ssize_t sys_read(int fd, const void *buf, size_t count)
{
	(void) fd;
	(void) buf;
	return count;
}
uint64_t sys_getpid()
{
	return current_process->pid;
}
uint64_t syscall_handler(uint64_t intno, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5)
{
	(void) arg4;
	(void) arg5;
	uint64_t returnval = 0;
	switch(intno)
	{
		case 0:
			returnval = (uint64_t)sys_write((int)arg1, (void*)arg2, arg3);
		case 1:
			returnval = (uint64_t)sys_read((int)arg1, (void*)arg2, arg3);
		case 4:
			returnval = (uint64_t)sys_getpid();
	}
	return returnval;
}
