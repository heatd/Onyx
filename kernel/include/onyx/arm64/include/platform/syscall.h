/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_ARM64_PLATFORM_SYSCALL_H
#define _ONYX_ARM64_PLATFORM_SYSCALL_H

#ifndef __ASSEMBLER__
#include <onyx/registers.h>

struct syscall_frame
{
    registers_t regs;
};

#endif
#endif
