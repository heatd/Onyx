/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifdef __is_onyx_kernel
#include <kernel/panic.h>
#endif
__attribute__ ((__noreturn__))
void abort(void)
{
#ifdef __is_onyx_kernel
	panic("abort()");
#else
#endif
	__builtin_unreachable();
}
