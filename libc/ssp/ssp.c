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
/**************************************************************************
 *
 *
 * File: ssp.c
 *
 * Description: Contains the implementation of the GCC stack protector functions
 *
 * Date: 2/2/2016
 *
 *
 **************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#ifdef __is_spartix_kernel
#include <kernel/panic.h>
#endif

#if UINT32_MAX == UINTPTR_MAX
#define STACK_CHK_GUARD 0xdeadc0de
#else
#define STACK_CHK_GUARD 0xdeadd00ddeadc0de
#endif

uintptr_t __stack_chk_guard = STACK_CHK_GUARD;
__attribute__((noreturn))
void __stack_chk_fail()
{
#if __STDC_HOSTED__
	abort(); // abort() right away, its unsafe!
#elif __is_spartix_kernel
	panic("Stack smashing detected");
#endif
}
