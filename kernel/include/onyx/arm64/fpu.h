/*
 * Copyright (c) 2023 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_ARM64_FPU_H
#define _ONYX_ARM64_FPU_H

#include <onyx/types.h>

struct fpstate
{
    u64 regs[64] __attribute__((aligned(16)));
    u32 fpsr;
    u32 fpcr;
};

#endif
