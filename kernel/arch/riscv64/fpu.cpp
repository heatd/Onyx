/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/fpu.h>
#include <onyx/riscv/features.h>
#include <onyx/riscv/intrinsics.h>

#include <onyx/utility.hpp>

static uint32_t isa_features;
size_t save_size = 0;
size_t save_alignment = 1;

void setup_fpu_area(unsigned char *address)
{
}

extern "C" {

void save_fpu_quad(void *address);
void save_fpu_double(void *address);
void save_fpu_single(void *address);

void restore_fpu_quad(void *address);
void restore_fpu_double(void *address);
void restore_fpu_single(void *address);
}

void save_fpu(void *address)
{
    if (isa_features & RISCV_FEATURE_DOUBLE_FP)
    {
        save_fpu_double(address);
    }
    else if (isa_features & RISCV_FEATURE_SINGLE_FP)
    {
        save_fpu_single(address);
    }
}

void restore_fpu(void *address)
{
    if (isa_features & RISCV_FEATURE_DOUBLE_FP)
    {
        restore_fpu_double(address);
    }
    else if (isa_features & RISCV_FEATURE_SINGLE_FP)
    {
        restore_fpu_single(address);
    }
}

void fpu_ptrace_getfpregs(void *fpregs, struct user_fpregs_struct *regs)
{
}

void fpu_init(void)
{
    isa_features = riscv_get_features();
    unsigned int register_width = 0;

    // Note: quad is unsupported because we can't assemble flq and fsq instructions
    if (isa_features & RISCV_FEATURE_DOUBLE_FP)
    {
        register_width = 8;
    }
    else if (isa_features & RISCV_FEATURE_SINGLE_FP)
    {
        register_width = 4;
    }

    if (!register_width)
        return; // no fp available

    save_alignment = register_width; // register loads/stores will be naturally aligned
    save_size = (register_width * 32) + 4 /* fcsr is 32-bits */;

    // Set FS to initial
    riscv_or_csr(RISCV_SSTATUS, 1 << 13);
}

size_t fpu_get_save_size(void)
{
    return save_size;
}

size_t fpu_get_save_alignment(void)
{
    return cul::max(0UL, save_alignment);
}
