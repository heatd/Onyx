/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_REGISTERS_H
#define _ONYX_REGISTERS_H

#ifdef __x86_64__

#ifndef __ASSEMBLER__

#include <stdbool.h>

#include <onyx/x86/segments.h>

typedef struct registers
{
    unsigned long ds;
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rbp;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long rdx;
    unsigned long rcx;
    unsigned long rbx;
    unsigned long rax;
    unsigned long int_no;
    unsigned long int_err_code;
    unsigned long rip;
    unsigned long cs;
    unsigned long rflags;
    unsigned long rsp;
    unsigned long ss;
} registers_t;

static inline bool in_kernel_space_regs(struct registers *regs)
{
    return regs->cs == KERNEL_CS;
}

#endif

#define REGISTER_OFF_DS           0
#define REGISTER_OFF_R15          8
#define REGISTER_OFF_R14          16
#define REGISTER_OFF_R13          24
#define REGISTER_OFF_R12          32
#define REGISTER_OFF_R11          40
#define REGISTER_OFF_R10          48
#define REGISTER_OFF_R9           56
#define REGISTER_OFF_R8           64
#define REGISTER_OFF_RBP          72
#define REGISTER_OFF_RSI          80
#define REGISTER_OFF_RDI          88
#define REGISTER_OFF_RDX          96
#define REGISTER_OFF_RCX          104
#define REGISTER_OFF_RBX          112
#define REGISTER_OFF_RAX          120
#define REGISTER_OFF_INT_NO       128
#define REGISTER_OFF_INT_ERR_CODE 136
#define REGISTER_OFF_RIP          144
#define REGISTER_OFF_CS           152
#define REGISTER_OFF_RFLAGS       160
#define REGISTER_OFF_RSP          168
#define REGISTER_OFF_SS           176

#elif defined(__riscv)

#include <stdbool.h>

#include <onyx/riscv/intrinsics.h>

typedef struct registers
{
    union {
        struct
        {
            unsigned long ra;
            unsigned long sp;
            unsigned long gp;
            unsigned long tp;
            unsigned long t0;
            unsigned long t1;
            unsigned long t2;
            unsigned long fp;
            unsigned long s1;
            unsigned long a0;
            unsigned long a1;
            unsigned long a2;
            unsigned long a3;
            unsigned long a4;
            unsigned long a5;
            unsigned long a6;
            unsigned long a7;
            unsigned long s2;
            unsigned long s3;
            unsigned long s4;
            unsigned long s5;
            unsigned long s6;
            unsigned long s7;
            unsigned long s8;
            unsigned long s9;
            unsigned long s10;
            unsigned long s11;
            unsigned long t3;
            unsigned long t4;
            unsigned long t5;
            unsigned long t6;
        };
        // x1 - x31 (epc is not included)
        unsigned long gpr[31];
    };

    unsigned long epc;
    unsigned long cause;
    unsigned long tval;
    unsigned long status;
} registers_t;

static inline bool in_kernel_space_regs(struct registers *regs)
{
    return regs->status & RISCV_SSTATUS_SPP;
}

#elif defined(__aarch64__)

using registers_t = struct registers
{
    unsigned long x[31];
    unsigned long sp;
    unsigned long pc;
    unsigned long pstate;
};

static inline bool in_kernel_space_regs(struct registers *regs)
{
    return (regs->pstate & 0b1111) == 0b0101;
}

#endif

#endif
