/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_X86_PLATFORM_INTERNAL_ABI_H
#define _ONYX_X86_PLATFORM_INTERNAL_ABI_H

#include <stdint.h>

namespace abi
{

struct internal_abi_layout
{
    uintptr_t self; // unused right now
    uintptr_t
        dummy0; // used to be dtv TODO: Maybe we want something like this for per-module percpu?
    uintptr_t dummy1[3];
    uintptr_t canary, canary2; // TODO: What's canary2 for?
};

} // namespace abi

#endif
