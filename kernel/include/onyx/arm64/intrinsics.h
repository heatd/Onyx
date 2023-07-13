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

#define msr(reg, value) ({ __asm__ __volatile__("msr " reg ", %0" ::"r"((unsigned long) value)); })
#define isb()           __asm__ __volatile__("isb" ::: "memory")

#define mrs(reg)                                             \
    ({                                                       \
        unsigned long ____val;                               \
        __asm__ __volatile__("mrs %0," reg : "=r"(____val)); \
        ____val;                                             \
    })

#define REG_TTBR0  "ttbr0_el1"
#define REG_TTBR1  "ttbr1_el1"
#define REG_ESR    "esr_el1"
#define REG_CNTPCT "cntpct_el0"
#define REG_CNTFRQ "cntfrq_el0"

#define dsb() __asm__ __volatile__("dsb sy" ::: "memory")
#endif
