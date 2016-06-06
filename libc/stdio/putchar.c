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

#if defined(__is_spartix_kernel)
#include <kernel/tty.h>
#endif
int putchar(int ic)
{
	char c = (char) ic;
#if defined(__is_spartix_kernel)
	tty_write(&c, sizeof(c));
#else
	(void)c;
#endif
	return ic;
}
