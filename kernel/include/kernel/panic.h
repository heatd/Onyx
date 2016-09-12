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
#ifndef _PANIC_H
#define _PANIC_H

#include <kernel/compiler.h>
#include <kernel/registers.h>
ARCH_SPECIFIC void halt();
ARCH_SPECIFIC void get_thread_ctx(registers_t* regs);
/* The functions halt and get_thread_ctx are architecture dependent, as they require manual assembly.
 * As so, its left for the architecture to implement these functions. The kernel expects them to be hooked.
 */
extern __attribute__ ((noreturn,cold,noinline))
void panic(const char* msg);
uintptr_t get_kernel_sym_by_name(char *name);
#endif
