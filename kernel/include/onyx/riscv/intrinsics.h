/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_RISCV_INTRINSICS_H
#define _ONYX_RISCV_INTRINSICS_H

#include <stdint.h>

template <typename Type>
static inline void mov_non_temporal(volatile Type *p, Type val)
{
    *p = val;
}

#define RISCV_SATP    "satp"
#define RISCV_STVEC   "stvec"
#define RISCV_SSTATUS "sstatus"

#define riscv_read_csr(register)                               \
    ({                                                         \
        unsigned long val;                                     \
        __asm__ __volatile__("csrr %0," register : "=r"(val)); \
        val;                                                   \
    })

#define riscv_write_csr(register, val) \
    ({ __asm__ __volatile__("csrw " register ", %0" ::"r"((unsigned long) val)); })

#define RISCV_SSTATUS_SPP (1 << 8) // 1 = exception happened in supervisor mode, else user
#define RISCV_SSTATUS_SIE (1 << 1) // 1 = Interrupts enabled in supervisor mode

#define RISCV_SCAUSE_INTERRUPT (1UL << 63)

#endif
