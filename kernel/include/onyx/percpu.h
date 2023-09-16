/*
 * Copyright (c) 2019 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_PERCPU_H
#define _ONYX_PERCPU_H
#include <stdbool.h>

#include <onyx/compiler.h>

#define PER_CPU_VAR(var)     __attribute__((section(".percpu"), used)) var
#define PER_CPU_VAR_ABI(var) __attribute__((section(".percpu.abi"), used)) var

#define PER_CPU_VAR_NOUNUSED(var) var __attribute__((section(".percpu")))

// The arch specific headers implement get_per_cpu() and *_per_cpu_N(),
// the macros below switch statement stuff

#if __x86_64__
#include <onyx/x86/percpu.h>
#elif __riscv
#include <onyx/riscv/percpu.h>
#elif __aarch64__
#include <onyx/arm64/percpu.h>
#else
#error "Unimplemented percpu stuff!"
#endif

#if 1

#define write_per_cpu(var, val)            \
    ({                                     \
        switch (sizeof(var))               \
        {                                  \
            case 1:                        \
                write_per_cpu_1(var, val); \
                break;                     \
            case 2:                        \
                write_per_cpu_2(var, val); \
                break;                     \
            case 4:                        \
                write_per_cpu_4(var, val); \
                break;                     \
            case 8:                        \
                write_per_cpu_8(var, val); \
                break;                     \
        }                                  \
    })

#define add_per_cpu(var, val)            \
    ({                                   \
        switch (sizeof(var))             \
        {                                \
            case 1:                      \
                add_per_cpu_1(var, val); \
                break;                   \
            case 2:                      \
                add_per_cpu_2(var, val); \
                break;                   \
            case 4:                      \
                add_per_cpu_4(var, val); \
                break;                   \
            case 8:                      \
                add_per_cpu_8(var, val); \
                break;                   \
        }                                \
    })

// INC/DEC operations can use the intrinsic ops defined
// by the arch percpu, or they fallback to add_per_cpu
#ifdef inc_per_cpu_1

#define inc_per_cpu(var)            \
    ({                              \
        switch (sizeof(var))        \
        {                           \
            case 1:                 \
                inc_per_cpu_1(var); \
                break;              \
            case 2:                 \
                inc_per_cpu_2(var); \
                break;              \
            case 4:                 \
                inc_per_cpu_4(var); \
                break;              \
            case 8:                 \
                inc_per_cpu_8(var); \
                break;              \
        }                           \
    })
#else
#define inc_per_cpu(var) add_per_cpu(var, 1)
#endif

#ifdef inc_per_cpu_1

#define inc_per_cpu(var)            \
    ({                              \
        switch (sizeof(var))        \
        {                           \
            case 1:                 \
                inc_per_cpu_1(var); \
                break;              \
            case 2:                 \
                inc_per_cpu_2(var); \
                break;              \
            case 4:                 \
                inc_per_cpu_4(var); \
                break;              \
            case 8:                 \
                inc_per_cpu_8(var); \
                break;              \
        }                           \
    })
#else
#define inc_per_cpu(var) add_per_cpu(var, 1)
#endif

#ifdef dec_per_cpu_1

#define dec_per_cpu(var)            \
    ({                              \
        switch (sizeof(var))        \
        {                           \
            case 1:                 \
                dec_per_cpu_1(var); \
                break;              \
            case 2:                 \
                dec_per_cpu_2(var); \
                break;              \
            case 4:                 \
                dec_per_cpu_4(var); \
                break;              \
            case 8:                 \
                dec_per_cpu_8(var); \
                break;              \
        }                           \
    })
#else
#define dec_per_cpu(var) add_per_cpu(var, -1)
#endif

#else

extern "C" unsigned long __raw_asm_get_per_cpu(size_t off, size_t size);
extern "C" void __raw_asm_write_per_cpu(size_t off, unsigned long val, size_t size);
extern "C" void __raw_asm_add_per_cpu(size_t off, unsigned long val, size_t size);

#define get_per_cpu_no_cast(var) __raw_asm_get_per_cpu((size_t) &var, sizeof(var))
#define get_per_cpu(var)         ((__typeof__(var)) __raw_asm_get_per_cpu((size_t) &var, sizeof(var)))
#define write_per_cpu(var, val) \
    __raw_asm_write_per_cpu((size_t) &var, (unsigned long) val, sizeof(var))
#define add_per_cpu(var, val) __raw_asm_add_per_cpu((size_t) &var, (unsigned long) val, sizeof(var))

#endif

extern unsigned long *percpu_bases;

void percpu_init();
unsigned long percpu_init_for_cpu(unsigned int cpu);
int percpu_map_master_copy();
unsigned long percpu_get_nr_bases();

unsigned long percpu_get_area(unsigned int cpu);

#define other_cpu_get_ptr(var, cpu)    ((__typeof__(var) *) (percpu_bases[cpu] + (unsigned long) &var))
#define other_cpu_get(var, cpu)        *other_cpu_get_ptr(var, cpu)
#define other_cpu_write(var, val, cpu) *other_cpu_get_ptr(var, cpu) = val
#define other_cpu_add(var, val, cpu)   *other_cpu_get_ptr(var, cpu) += val

#define get_per_cpu_ptr_any(var, cpu) \
    (cpu == get_cpu_nr() ? get_per_cpu_ptr(var) : other_cpu_get_ptr(var, cpu))
#define get_per_cpu_any(var, cpu) (cpu == get_cpu_nr() ? get_per_cpu(var) : other_cpu_get(var, cpu))

#define write_per_cpu_any(var, val, cpu)    \
    do                                      \
    {                                       \
        if (cpu == get_cpu_nr())            \
            write_per_cpu(var, val);        \
        else                                \
            other_cpu_write(var, val, cpu); \
    } while (0)

#define add_per_cpu_any(var, val, cpu)    \
    do                                    \
    {                                     \
        if (cpu == get_cpu_nr())          \
            add_per_cpu(var, val);        \
        else                              \
            other_cpu_add(var, val, cpu); \
    } while (0)

#ifdef __cplusplus
extern "C"
#else
extern
#endif
    unsigned long __cpu_base;

#define get_per_cpu_ptr_no_cast(var)                         \
    ({                                                       \
        unsigned long ___cpu_base = get_per_cpu(__cpu_base); \
        ((unsigned long) &var + ___cpu_base);                \
    })

#define get_per_cpu_ptr(var) ({ (__typeof__(var) *) get_per_cpu_ptr_no_cast(var); })

/* Fallback for architectures that do not implement stable reading */
#ifndef get_per_cpu_stable
#define get_per_cpu_stable(a) get_per_cpu(a)
#endif

#endif
