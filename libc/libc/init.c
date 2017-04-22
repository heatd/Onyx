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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/syscall.h>
#include <sys/mman.h>

char **environ = NULL;
extern void __initialize_ssp();
void __ret_sig()
{
	//syscall(SYS_sigreturn, (uint64_t)-1ULL);
}
void _init_standard_libc(char **envp)
{
	/* Initialize sbrk(3) */
	void *addr = mmap(NULL, 4096, PROT_WRITE | PROT_READ, MAP_ANONYMOUS, 0, 0);

	/* Any failure here results in an exit(1), as we have no malloc or sbrk */
	if(!addr)
		exit(1);
	if(brk(addr))
		exit(1);
	environ = envp;
	__initialize_ssp();
	//syscall(SYS_sigreturn, (uint64_t)(void*) __ret_sig);
}
