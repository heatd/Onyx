/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_FPU_H
#define _ONYX_FPU_H

#include <stdbool.h>
#include <stddef.h>

#include <onyx/compiler.h>

#include <uapi/user.h>

__BEGIN_CDECLS

void setup_fpu_area(unsigned char *address);
void save_fpu(void *address);
void restore_fpu(void *address);
struct user_fpregs_struct;
void fpu_ptrace_getfpregs(void *fpregs, struct user_fpregs_struct *regs);
void fpu_init(void);
size_t fpu_get_save_size(void);
size_t fpu_get_save_alignment(void);

/**
 * @brief Initialize the FPU state slab cache
 *
 */
void fpu_init_cache();

/**
 * @brief Allocate an FPU state object from the allocator
 *
 * @return Pointer to FPU state, or nullptr
 */
void *fpu_allocate_state();

/**
 * @brief Free FPU state object
 *
 * @param state Pointer to state
 */
void fpu_free_state(void *state);

__END_CDECLS

#endif
