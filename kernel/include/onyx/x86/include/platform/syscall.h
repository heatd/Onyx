/*
 * Copyright (c) 2018 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_X86_SYSCALL_H
#define _ONYX_X86_SYSCALL_H

#ifndef __ASSEMBLER__
struct syscall_frame
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
};

#endif

#define SYSCALL_FRAME_CLOBBERED_SIZE 7 * 8

#define SYSCALL_FRAME_SIZE 18 * 8

#endif
