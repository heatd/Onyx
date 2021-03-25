/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_RISCV_PLATFORM_SYSCALL_H
#define _ONYX_RISCV_PLATFORM_SYSCALL_H

#include <sys/syscall.h>

#define NR_SYSCALL_MAX		142

#ifndef __ASSEMBLER__
struct syscall_frame
{
	unsigned long user_sp;
};

#endif
#endif
