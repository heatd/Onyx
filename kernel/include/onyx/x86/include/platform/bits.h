/*
 * Copyright (c) 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/* for count_bits */
#include <onyx/cpu.h>
#include <onyx/x86/alternatives.h>

static unsigned int __fast_popcount32(unsigned r)
{
    unsigned int a;
    ALTERNATIVE_CALL_1_1("call __popcountsi2", "popcnt %1, %0", X86_FEATURE_POPCNT, "=a"(a),
                         "D"(r));
    return a;
}

static unsigned int __fast_popcount64(unsigned long r)
{
    unsigned int a;
    ALTERNATIVE_CALL_1_1("call __popcountdi2", "popcnt %1, %0", X86_FEATURE_POPCNT, "=a"(a),
                         "D"(r));
    return a;
}

#ifdef __cplusplus
template <typename Type>
unsigned int count_bits(Type val)
{
    static_assert(is_integral_v<Type>);
    static_assert(sizeof(val) <= sizeof(unsigned long));

    if (__builtin_constant_p(val))
        return __builtin_popcountg(val);

    if constexpr (sizeof(Type) == sizeof(unsigned long))
        return __fast_popcount64((unsigned long) val);

    /* Anything smaller gets converted to unsigned int and dealt with */
    return __fast_popcount32((unsigned int) val);
}

#define __HAZ_COUNT_BITS
#endif
