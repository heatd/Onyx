/*
 * Copyright (c) 2016 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_BITS_H
#define _ONYX_BITS_H

#ifdef __cplusplus
#include <onyx/is_integral.h>
#endif

#if __has_include(<platform/bits.h>)
#include <platform/bits.h>
#endif

#if defined(__cplusplus) && !defined(__HAZ_COUNT_BITS)

template <typename Type>
unsigned int count_bits(Type val)
{
    static_assert(is_integral_v<Type>);

    if constexpr (sizeof(Type) == sizeof(unsigned long))
    {
        return __builtin_popcountl(val);
    }
    else if constexpr (sizeof(Type) == sizeof(unsigned long long))
    {
        return __builtin_popcountll(val);
    }
    else
    {
        // Anything smaller than unsigned long gets converted to an unsigned
        // int, as it's the smallest type.
        return __builtin_popcount(val);
    }
}

#endif

#endif
