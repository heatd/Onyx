/*
 * Copyright (c) 2021 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_X86_PERCPU_H
#define _ONYX_X86_PERCPU_H

#include <stdint.h>

#ifdef __clang__

// Clang doesn't implement %p yet
// TODO: Implement and submit a PR?
// clang-format off
#define ____PCPU_VAR(index)             " %%gs:%c" index
#define __PCPU_CONSTRAINT(var) "i"((unsigned long) &var)
// clang-format on
#else
// GCC rejects the trick we use for clang, so use the "proper" solution here
// clang-format off
#define ____PCPU_VAR(index)             " %%gs:%p" index
#define __PCPU_CONSTRAINT(var) "m"(var)
// clang-format on
#endif

#define __PCPU_VAR ____PCPU_VAR("1")

#define get_per_cpu_x86_internal(var, suffix, type, qualifiers)                                    \
    ({                                                                                             \
        type __val;                                                                                \
        __asm__ qualifiers("mov" suffix __PCPU_VAR ", %0" : "=r"(__val) : __PCPU_CONSTRAINT(var)); \
        (__typeof__(var)) (unsigned long) __val;                                                   \
    })

#define get_per_cpu_1(var) get_per_cpu_x86_internal(var, "b", uint8_t, __volatile__)
#define get_per_cpu_2(var) get_per_cpu_x86_internal(var, "w", uint16_t, __volatile__)
#define get_per_cpu_4(var) get_per_cpu_x86_internal(var, "l", uint32_t, __volatile__)
#define get_per_cpu_8(var) get_per_cpu_x86_internal(var, "q", uint64_t, __volatile__)

#define stable_get_per_cpu_1(var) get_per_cpu_x86_internal(var, "b", uint8_t, )
#define stable_get_per_cpu_2(var) get_per_cpu_x86_internal(var, "w", uint16_t, )
#define stable_get_per_cpu_4(var) get_per_cpu_x86_internal(var, "l", uint32_t, )
#define stable_get_per_cpu_8(var) get_per_cpu_x86_internal(var, "q", uint64_t, )

#define get_per_cpu(var)                \
    ({                                  \
        __typeof__(var) v;              \
        switch (sizeof(var))            \
        {                               \
            case 1:                     \
                v = get_per_cpu_1(var); \
                break;                  \
            case 2:                     \
                v = get_per_cpu_2(var); \
                break;                  \
            case 4:                     \
                v = get_per_cpu_4(var); \
                break;                  \
            case 8:                     \
                v = get_per_cpu_8(var); \
                break;                  \
        }                               \
        v;                              \
    })

#define get_per_cpu_stable(var)                \
    ({                                         \
        __typeof__(var) v;                     \
        switch (sizeof(var))                   \
        {                                      \
            case 1:                            \
                v = stable_get_per_cpu_1(var); \
                break;                         \
            case 2:                            \
                v = stable_get_per_cpu_2(var); \
                break;                         \
            case 4:                            \
                v = stable_get_per_cpu_4(var); \
                break;                         \
            case 8:                            \
                v = stable_get_per_cpu_8(var); \
                break;                         \
        }                                      \
        v;                                     \
    })

#define get_per_cpu_no_cast(var)                                                               \
    ({                                                                                         \
        unsigned long __val;                                                                   \
        __asm__ __volatile__("movq" __PCPU_VAR ", %0" : "=r"(__val) : __PCPU_CONSTRAINT(var)); \
        __val;                                                                                 \
    })

#define write_per_cpu_internal(var, val, suffix, type)                                           \
    ({                                                                                           \
        __asm__ __volatile__("mov" suffix " %0," __PCPU_VAR ::"r"(((type) (unsigned long) val)), \
                             __PCPU_CONSTRAINT(var));                                            \
    })

#define write_per_cpu_1(var, val) write_per_cpu_internal(var, val, "b", uint8_t)
#define write_per_cpu_2(var, val) write_per_cpu_internal(var, val, "w", uint16_t)
#define write_per_cpu_4(var, val) write_per_cpu_internal(var, val, "l", uint32_t)
#define write_per_cpu_8(var, val) write_per_cpu_internal(var, val, "q", uint64_t)

#define add_per_cpu_internal(var, val, suffix, type)                                           \
    ({                                                                                         \
        __asm__ __volatile__("add" suffix " %0," __PCPU_VAR ::"r"((type) (unsigned long) val), \
                             __PCPU_CONSTRAINT(var));                                          \
    })

#define add_per_cpu_1(var, val) add_per_cpu_internal(var, val, "b", uint8_t)
#define add_per_cpu_2(var, val) add_per_cpu_internal(var, val, "w", uint16_t)
#define add_per_cpu_4(var, val) add_per_cpu_internal(var, val, "l", uint32_t)
#define add_per_cpu_8(var, val) add_per_cpu_internal(var, val, "q", uint64_t)

#define inc_per_cpu_internal(var, suffix, type) \
    ({ __asm__ __volatile__("inc" suffix ____PCPU_VAR("0")::__PCPU_CONSTRAINT(var)); })

#define inc_per_cpu_1(var) inc_per_cpu_internal(var, "b", uint8_t)
#define inc_per_cpu_2(var) inc_per_cpu_internal(var, "w", uint16_t)
#define inc_per_cpu_4(var) inc_per_cpu_internal(var, "l", uint32_t)
#define inc_per_cpu_8(var) inc_per_cpu_internal(var, "q", uint64_t)

#define dec_per_cpu_internal(var, suffix, type) \
    ({ __asm__ __volatile__("dec" suffix ____PCPU_VAR("0")::__PCPU_CONSTRAINT(var)); })

#define dec_per_cpu_1(var) dec_per_cpu_internal(var, "b", uint8_t)
#define dec_per_cpu_2(var) dec_per_cpu_internal(var, "w", uint16_t)
#define dec_per_cpu_4(var) dec_per_cpu_internal(var, "l", uint32_t)
#define dec_per_cpu_8(var) dec_per_cpu_internal(var, "q", uint64_t)

#define dec_and_test_pcpu_internal(var, suffix, type)       \
    ({                                                      \
        int cz;                                             \
        __asm__ __volatile__("dec" suffix ____PCPU_VAR("1") \
                             : "=@ccz"(cz)                  \
                             : __PCPU_CONSTRAINT(var));     \
        cz;                                                 \
    })

#define dec_and_test_pcpu_1(var) dec_and_test_pcpu_internal(var, "b", uint8_t)
#define dec_and_test_pcpu_2(var) dec_and_test_pcpu_internal(var, "w", uint16_t)
#define dec_and_test_pcpu_4(var) dec_and_test_pcpu_internal(var, "l", uint32_t)
#define dec_and_test_pcpu_8(var) dec_and_test_pcpu_internal(var, "q", uint64_t)

#endif
