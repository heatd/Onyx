/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_RISCV_PLATFORM_INTERNAL_ABI_H
#define _ONYX_RISCV_PLATFORM_INTERNAL_ABI_H

#ifndef __ASSEMBLER__

#include <stdint.h>

namespace abi
{

struct internal_abi_layout
{
    uintptr_t self; // unused right now
    uintptr_t
        dummy0; // used to be dtv TODO: Maybe we want something like this for per-module percpu?
    unsigned long user_stack, kernel_stack;
    uintptr_t dummy1[1];
    uintptr_t canary, canary2; // TODO: What's canary2 for?
};

} // namespace abi

#endif

#define ABI_USER_STACK_OFFSET   16
#define ABI_KERNEL_STACK_OFFSET 24
#endif
