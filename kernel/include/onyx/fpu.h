/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_FPU_H
#define _ONYX_FPU_H

#include <stdbool.h>
#include <sys/user.h>

#ifdef __x86_64__

extern bool avx_supported;

#endif

void setup_fpu_area(unsigned char *address);
void save_fpu(void *address);
void restore_fpu(void *address);
void fpu_ptrace_getfpregs(void *fpregs, struct user_fpregs_struct *regs);
void fpu_init(void);
size_t fpu_get_save_size(void);
size_t fpu_get_save_alignment(void);

#endif
