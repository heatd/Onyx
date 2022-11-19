/*
 * Copyright (c) 2021 Pedro Falcato
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
#define __PCPU_VAR             " %%gs:%c1"
#define __PCPU_CONSTRAINT(var) "i"((unsigned long) &var)
// clang-format on
#else
// GCC rejects the trick we use for clang, so use the "proper" solution here
// clang-format off
#define __PCPU_VAR             " %%gs:%p1"
#define __PCPU_CONSTRAINT(var) "m"(var)
// clang-format on
#endif

#define get_per_cpu_x86_internal(var, suffix, type)                                                \
    ({                                                                                             \
        type val;                                                                                  \
        __asm__ __volatile__("mov" suffix __PCPU_VAR ", %0" : "=r"(val) : __PCPU_CONSTRAINT(var)); \
        (__typeof__(var)) (unsigned long) val;                                                     \
    })

#define get_per_cpu_1(var) get_per_cpu_x86_internal(var, "b", uint8_t)
#define get_per_cpu_2(var) get_per_cpu_x86_internal(var, "w", uint16_t)
#define get_per_cpu_4(var) get_per_cpu_x86_internal(var, "l", uint32_t)
#define get_per_cpu_8(var) get_per_cpu_x86_internal(var, "q", uint64_t)

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

#define get_per_cpu_no_cast(var)                                                             \
    ({                                                                                       \
        unsigned long val;                                                                   \
        __asm__ __volatile__("movq" __PCPU_VAR ", %0" : "=r"(val) : __PCPU_CONSTRAINT(var)); \
        val;                                                                                 \
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

#endif
