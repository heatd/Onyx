/*
 * Copyright (c) 2016 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/cpu.h>

extern "C"
__attribute__((noreturn, cold))
void halt()
{
	DISABLE_INTERRUPTS();

	while(true) cpu_sleep();

	__builtin_unreachable();
}
