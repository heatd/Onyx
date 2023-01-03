/*
 * Copyright (c) 2023 Pedro Falcato
 * Copyright (c) 2019 Musl libc authors
 *
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_UAPI_BITS_RISCV_H
#define _ONYX_UAPI_BITS_RISCV_H

typedef unsigned long __riscv_mc_gp_state[32];

struct __riscv_mc_f_ext_state
{
    unsigned int __f[32];
    unsigned int __fcsr;
};

struct __riscv_mc_d_ext_state
{
    unsigned long long __f[32];
    unsigned int __fcsr;
};

struct __riscv_mc_q_ext_state
{
    unsigned long long __f[64] __attribute__((aligned(16)));
    unsigned int __fcsr;
    unsigned int __reserved[3];
};

union __riscv_mc_fp_state {
    struct __riscv_mc_f_ext_state __f;
    struct __riscv_mc_d_ext_state __d;
    struct __riscv_mc_q_ext_state __q;
};

typedef struct mcontext_t
{
    __riscv_mc_gp_state __gregs;
    union __riscv_mc_fp_state __fpregs;
} mcontext_t;

#endif
