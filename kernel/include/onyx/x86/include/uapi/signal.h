/*
 * Copyright (c) 2023 Pedro Falcato
 * Copyright (c) 2019 Musl libc authors
 *
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_UAPI_SIGNAL_H
#define _ONYX_UAPI_SIGNAL_H

#define REG_R8      0
#define REG_R9      1
#define REG_R10     2
#define REG_R11     3
#define REG_R12     4
#define REG_R13     5
#define REG_R14     6
#define REG_R15     7
#define REG_RDI     8
#define REG_RSI     9
#define REG_RBP     10
#define REG_RBX     11
#define REG_RDX     12
#define REG_RAX     13
#define REG_RCX     14
#define REG_RSP     15
#define REG_RIP     16
#define REG_EFL     17
#define REG_CSGSFS  18
#define REG_ERR     19
#define REG_TRAPNO  20
#define REG_OLDMASK 21
#define REG_CR2     22

typedef long long greg_t, gregset_t[23];
typedef struct _fpstate
{
    unsigned short cwd, swd, ftw, fop;
    unsigned long long rip, rdp;
    unsigned mxcsr, mxcr_mask;
    struct
    {
        unsigned short significand[4], exponent, padding[3];
    } _st[8];
    struct
    {
        unsigned element[4];
    } _xmm[16];
    unsigned padding[24];
} *fpregset_t;

typedef struct
{
    gregset_t gregs;
    fpregset_t fpregs;
    unsigned long long __reserved1[8];
} mcontext_t;

/* Include generic signal definitions, after our struct code */
#include <uapi/signal-generic.h>

#endif
