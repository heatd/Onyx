/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>

#if defined(__is_onyx_kernel)
#include <kernel/tty.h>
#endif
int putchar(int ic)
{
	char c = (char) ic;
#if defined(__is_onyx_kernel)
	tty_write(&c, sizeof(c));
#else
	(void)c;
#endif
	return ic;
}
