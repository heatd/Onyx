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
#include <kernel/registers.h>
#include <stdio.h>
__attribute__((noreturn,cold))
void halt()
{
	__asm__ __volatile__("cli \t\n hlt");
	// If execution goes past this, I don't know what the hell our kernel is running on
	for(;;);
	__builtin_unreachable();
}
