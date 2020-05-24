/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/cpu.h>

__attribute__((noreturn, cold))
void halt()
{
	DISABLE_INTERRUPTS();

	while(true) __asm__ __volatile__("hlt");

	__builtin_unreachable();
}
