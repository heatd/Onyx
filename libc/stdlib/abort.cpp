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
#ifdef __is_spartix_kernel
#include <kernel/panic.h>
#endif
extern "C" __attribute__ ((__noreturn__))
void abort(void)
{
#ifdef __is_spartix_kernel
	panic("abort()");
#else
#endif
	__builtin_unreachable();
}
