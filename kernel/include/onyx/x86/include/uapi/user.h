/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_X86_UAPI_USER_H
#define _ONYX_X86_UAPI_USER_H
#undef __WORDSIZE
#define __WORDSIZE 64

#include <onyx/types.h>

typedef struct user_fpregs_struct
{
    __u16 cwd, swd, ftw, fop;
    __u64 rip, rdp;
    __u32 mxcsr, mxcr_mask;
    __u32 st_space[32], xmm_space[64], padding[24];
} elf_fpregset_t;

struct user_regs_struct
{
    unsigned long r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8;
    unsigned long rax, rcx, rdx, rsi, rdi, orig_rax, rip;
    unsigned long cs, eflags, rsp, ss, fs_base, gs_base, ds, es, fs, gs;
};
#define ELF_NGREG 27
typedef unsigned long long elf_greg_t;
typedef struct user_regs_struct elf_gregset_t;

struct user
{
    struct user_regs_struct regs;
    int u_fpvalid;
    struct user_fpregs_struct i387;
    unsigned long u_tsize;
    unsigned long u_dsize;
    unsigned long u_ssize;
    unsigned long start_code;
    unsigned long start_stack;
    long signal;
    int reserved;
    struct user_regs_struct *u_ar0;
    struct user_fpregs_struct *u_fpstate;
    unsigned long magic;
    char u_comm[32];
    unsigned long u_debugreg[8];
};

#define PAGE_MASK            (~(PAGE_SIZE - 1))
#define NBPG                 PAGE_SIZE
#define UPAGES               1
#define HOST_TEXT_START_ADDR (u.start_code)
#define HOST_STACK_END_ADDR  (u.start_stack + u.u_ssize * NBPG)

#endif
