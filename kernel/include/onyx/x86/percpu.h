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

#define get_per_cpu_x86_internal(var, suffix, type)                               \
    ({                                                                            \
        type val;                                                                 \
        __asm__ __volatile__("mov" suffix " %%gs:%1, %0" : "=r"(val) : "m"(var)); \
        (__typeof__(var)) (unsigned long) val;                                    \
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

#define get_per_cpu_no_cast(var)          \
    ({                                    \
        unsigned long val;                \
        __asm__ __volatile__("movq %%gs:" \
                             "%1, %0"     \
                             : "=r"(val)  \
                             : "m"(var)); \
        val;                              \
    })

#define write_per_cpu_1(var, val)                                         \
    ({                                                                    \
        __asm__ __volatile__("movb %0, %%gs:"                             \
                             "%1" ::"r"(((uint8_t) (unsigned long) val)), \
                             "m"(var));                                   \
    })

#define write_per_cpu_2(var, val)             \
    ({                                        \
        __asm__ __volatile__("movw %0, %%gs:" \
                             "%1" ::"r"(val), \
                             "m"(var));       \
    })

#define write_per_cpu_4(var, val)             \
    ({                                        \
        __asm__ __volatile__("movl %0, %%gs:" \
                             "%1" ::"r"(val), \
                             "m"(var));       \
    })

#define write_per_cpu_8(var, val)                             \
    ({                                                        \
        __asm__ __volatile__("movq %0, %%gs:"                 \
                             "%1" ::"r"((unsigned long) val), \
                             "m"(var));                       \
    })

#define add_per_cpu_1(var, val)               \
    ({                                        \
        __asm__ __volatile__("addb %0, %%gs:" \
                             "%1" ::"r"(val), \
                             "m"(var));       \
    })

#define add_per_cpu_2(var, val)               \
    ({                                        \
        __asm__ __volatile__("addw %0, %%gs:" \
                             "%1" ::"r"(val), \
                             "m"(var));       \
    })

#define add_per_cpu_4(var, val)               \
    ({                                        \
        __asm__ __volatile__("addl %0, %%gs:" \
                             "%1" ::"r"(val), \
                             "m"(var));       \
    })

#define add_per_cpu_8(var, val)                               \
    ({                                                        \
        __asm__ __volatile__("addq %0, %%gs:"                 \
                             "%1" ::"r"((unsigned long) val), \
                             "m"(var));                       \
    })

#endif
