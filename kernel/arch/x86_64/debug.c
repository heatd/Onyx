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
#include <kernel/registers.h>
#include <stdio.h>
__attribute__((noreturn,cold))
void halt()
{
	asm volatile("cli \t\n hlt");
	// If execution goes past this, I don't know what the hell our kernel is running on
	for(;;);
	__builtin_unreachable();
}
