/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_ARM64_PERCPU_H
#define _ONYX_ARM64_PERCPU_H

#include <stdint.h>

#include <onyx/compiler.h>

static inline unsigned long arm64_get_tpidr()
{
    unsigned long thread_pointer = 0;
    __asm__("mrs %0, tpidr_el1" : "=r"(thread_pointer));
    return thread_pointer;
}

#define get_per_cpu(var)                                  \
    ({                                                    \
        unsigned long tp = arm64_get_tpidr();             \
        *(__typeof__(var) *) (tp + (unsigned long) &var); \
    })

#define get_per_cpu_no_cast(var)                        \
    ({                                                  \
        unsigned long tp = arm64_get_tpidr();           \
        *(unsigned long *) (tp + (unsigned long) &var); \
    })

#define write_per_cpu_generic(var, val, type)               \
    ({                                                      \
        unsigned long tp = arm64_get_tpidr();               \
        type *ptr = (type *) (tp + (unsigned long) &var);   \
        write_once<type>(*ptr, (type) (unsigned long) val); \
    })

#define write_per_cpu_1(var, val) write_per_cpu_generic(var, val, uint8_t)
#define write_per_cpu_2(var, val) write_per_cpu_generic(var, val, uint16_t)
#define write_per_cpu_4(var, val) write_per_cpu_generic(var, val, uint32_t)
#define write_per_cpu_8(var, val) write_per_cpu_generic(var, val, uint64_t)

#define add_per_cpu_generic(var, val, bytes) \
    ({                                       \
        unsigned long v = get_per_cpu(var);  \
        write_per_cpu_##bytes(var, v + val); \
    })

#define add_per_cpu_1(var, val) add_per_cpu_generic(var, val, 1)
#define add_per_cpu_2(var, val) add_per_cpu_generic(var, val, 2)
#define add_per_cpu_4(var, val) add_per_cpu_generic(var, val, 4)
#define add_per_cpu_8(var, val) add_per_cpu_generic(var, val, 8)

#endif
