/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_RISCV_PERCPU_H
#define _ONYX_RISCV_PERCPU_H

#include <stdint.h>

#define RISCV_PREPARE_TLS_ADDRESS "la a0, %1; add a0, a0, tp;"

#define get_per_cpu(var)                                              \
    ({                                                                \
        unsigned long val;                                            \
        __asm__ __volatile__(RISCV_PREPARE_TLS_ADDRESS " ld %0, (a0)" \
                             : "=r"(val)                              \
                             : "i"(&var)                              \
                             : "a0");                                 \
        (__typeof__(var)) val;                                        \
    })

#define get_per_cpu_no_cast(var)                                      \
    ({                                                                \
        unsigned long val;                                            \
        __asm__ __volatile__(RISCV_PREPARE_TLS_ADDRESS " ld %0, (a0)" \
                             : "=r"(val)                              \
                             : "i"(&var)                              \
                             : "a0");                                 \
        val;                                                          \
    })

#define write_per_cpu_generic(var, val, isize)                                             \
    ({                                                                                     \
        __asm__ __volatile__(RISCV_PREPARE_TLS_ADDRESS " s" isize " %0, 0(a0)" ::"r"(val), \
                             "i"(&var)                                                     \
                             : "a0");                                                      \
    })

#define write_per_cpu_1(var, val) write_per_cpu_generic(var, val, "b")
#define write_per_cpu_2(var, val) write_per_cpu_generic(var, val, "h")
#define write_per_cpu_4(var, val) write_per_cpu_generic(var, val, "w")
#define write_per_cpu_8(var, val) write_per_cpu_generic(var, val, "d")

#define add_per_cpu_generic(var, val, bytes) \
    ({                                       \
        unsigned long v = get_per_cpu(var);  \
        write_per_cpu_##bytes(var, v + val); \
    })

#define add_per_cpu_1(var, val) add_per_cpu_generic(var, val, 1)
#define add_per_cpu_2(var, val) add_per_cpu_generic(var, val, 2)
#define add_per_cpu_4(var, val) add_per_cpu_generic(var, val, 4)
#define add_per_cpu_8(var, val) add_per_cpu_generic(var, val, 8)

#define riscv_get_tp()                   \
    ({                                   \
        unsigned long tp;                \
        __asm__("mv %0, tp" : "=r"(tp)); \
        tp;                              \
    })

#endif
