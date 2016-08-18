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
int syscall_handler(uint64_t intno, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5)
{
	(void) arg2;
	(void) arg3;
	(void) arg4;
	(void) arg5;
	switch(intno)
	{
		case 0:
			printf("%s", arg1);
	}
	return 0;
}
