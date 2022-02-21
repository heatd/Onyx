/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_ARM64_INTRINSICS_H
#define _ONYX_ARM64_INTRINSICS_H

#include <stdint.h>

template <typename Type>
static inline void mov_non_temporal(volatile Type *p, Type val)
{
    *p = val;
}

#endif
