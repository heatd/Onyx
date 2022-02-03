/*
 * Copyright (c) 2016 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
/**************************************************************************
 *
 *
 * File: compiler.h
 *
 * Description: Contains GCC specific features and builtins
 *
 * Date: 1/2/2016
 *
 *
 **************************************************************************/
#ifndef _ONYX_COMPILER_H
#define _ONYX_COMPILER_H

#include <stdint.h>

#ifdef __cplusplus
#include <onyx/is_integral.h>
#endif

#ifndef __GNUC__
#error "The OS needs to be compiled using GCC/clang"
#endif /*__GNUC__ */
#ifndef __onyx__
#error "Onyx needs to be compiled using a Onyx Cross Compiler"
#endif /* __onyx__ */

#define FUNC_NO_DISCARD             __attribute__((warn_unused_result))
#define align(x)                    __attribute__((aligned(x)))
#define __align_cache               align(16)
#define likely(x)                   __builtin_expect(!!(x), 1)
#define unlikely(x)                 __builtin_expect(!!(x), 0)
#define prefetch(...)               __builtin_prefetch(__VA_ARGS__)
#define ASSUME_ALIGNED(x, y)        __builtin_assume_aligned(x, y)
#define ARCH_SPECIFIC               extern
#define UNUSED_PARAMETER(x)         (void) x
#define UNUSED(x)                   UNUSED_PARAMETER(x)
#define __init                      __attribute__((constructor))
#define weak_alias(name, aliasname) _weak_alias(name, aliasname)
#define _weak_alias(name, aliasname) \
    extern __typeof(name) aliasname __attribute__((weak, alias(#name)));

#define strong_alias(name, aliasname) _strong_alias(name, aliasname)
#define _strong_alias(name, aliasname) \
    extern __typeof(name) aliasname __attribute__((alias(#name)));

#define strong_alias_c_name(name, aliasname) _strong_alias_c_name(name, aliasname)
#define _strong_alias_c_name(name, aliasname) \
    extern "C" __typeof(name) aliasname __attribute__((alias(#name)));

#define USED_FUNC __attribute__((used))
#ifdef __x86_64__

static inline uint64_t rdtsc(void)
{
    union {
        uint64_t value;
        uint32_t lohi[2];
    } v;

    /* TODO: Alternativesssssssssssssssssssssssssssssssssssssssssssssssssss
     * we can't use rdtscp without them.
     */
    __asm__ __volatile__("lfence; rdtsc" : "=a"(v.lohi[0]), "=d"(v.lohi[1])::"ecx");
    return v.value;
}

#endif

#ifdef __cplusplus

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

#define add_check_overflow(op1, op2, res) __builtin_add_overflow(op1, op2, res)

#define ___PASTE(a, b) a##b
#define __PASTE(a, b)  ___PASTE(a, b)

#define COMPILER_BARRIER() __asm__ __volatile__("" ::: "memory")
#define ilog2(X)           ((unsigned) (8 * sizeof(unsigned long long) - __builtin_clzll((X)) - 1))
#define ALIGN_TO(x, y)     (((unsigned long) x + (y - 1)) & -y)

#define OPTIMISE_DEBUG __attribute__((optimize("Og")))

#define USED __attribute__((used))

#ifdef __x86_64__

#define write_memory_barrier() __asm__ __volatile__("sfence" ::: "memory")
#define read_memory_barrier()  __asm__ __volatile__("lfence" ::: "memory")

#elif defined(__riscv)

#define write_memory_barrier() __asm__ __volatile__("fence" ::: "memory")
#define read_memory_barrier()  __asm__ __volatile__("fence" ::: "memory")

#endif

#ifdef __cplusplus

template <typename Type>
inline Type read_once(const Type& t)
{
    return *((volatile Type*) &t);
}

template <typename Type>
inline void write_once(const Type& t, Type val)
{
    *((volatile Type*) &t) = val;
}

#endif

#define UNREACHABLE() __builtin_unreachable()

#endif /* COMPILER_H */
