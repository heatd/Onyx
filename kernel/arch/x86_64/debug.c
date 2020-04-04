/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

__attribute__((noreturn, cold))
void halt()
{
	__asm__ __volatile__("cli \t\n hlt");
	// If execution goes past this, I don't know what the hell our kernel is running on
	for(;;);
	__builtin_unreachable();
}
