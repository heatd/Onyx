/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/arm64/fpu.h>
#include <onyx/fpu.h>
#include <onyx/init.h>
#include <onyx/mm/slab.h>
#include <onyx/types.h>

void setup_fpu_area(unsigned char *address)
{
}

void save_fpu(void *address)
{
    __asm__ __volatile__("stp q0, q1, [%0, #16 * 0]\n\t"
                         "stp q2, q3, [%0, #16 * 2]\n\t"
                         "stp q4, q5, [%0, #16 * 4]\n\t"
                         "stp q6, q7, [%0, #16 * 6]\n\t"
                         "stp q8, q9, [%0, #16 * 8]\n\t"
                         "stp q10, q11, [%0, #16 * 10]\n\t"
                         "stp q12, q13, [%0, #16 * 12]\n\t"
                         "stp q14, q15, [%0, #16 * 14]\n\t"
                         "stp q16, q17, [%0, #16 * 16]\n\t"
                         "stp q18, q19, [%0, #16 * 18]\n\t"
                         "stp q20, q21, [%0, #16 * 20]\n\t"
                         "stp q22, q23, [%0, #16 * 22]\n\t"
                         "stp q24, q25, [%0, #16 * 24]\n\t"
                         "stp q26, q27, [%0, #16 * 26]\n\t"
                         "stp q28, q29, [%0, #16 * 28]\n\t"
                         "stp q30, q31, [%0, #16 * 30]\n\t"
                         "mrs x1, fpsr\n\t"
                         "str w1, [%0, #16 * 32]\n\t"
                         "mrs x1, fpcr\n\t"
                         "str w1, [%0, #16 * 32 + 4]\n" ::"r"(address)
                         : "x1", "memory");
}

void restore_fpu(void *address)
{
    __asm__ __volatile__("ldp q0, q1, [%0, #16 * 0]\n\t"
                         "ldp q2, q3, [%0, #16 * 2]\n\t"
                         "ldp q4, q5, [%0, #16 * 4]\n\t"
                         "ldp q6, q7, [%0, #16 * 6]\n\t"
                         "ldp q8, q9, [%0, #16 * 8]\n\t"
                         "ldp q10, q11, [%0, #16 * 10]\n\t"
                         "ldp q12, q13, [%0, #16 * 12]\n\t"
                         "ldp q14, q15, [%0, #16 * 14]\n\t"
                         "ldp q16, q17, [%0, #16 * 16]\n\t"
                         "ldp q18, q19, [%0, #16 * 18]\n\t"
                         "ldp q20, q21, [%0, #16 * 20]\n\t"
                         "ldp q22, q23, [%0, #16 * 22]\n\t"
                         "ldp q24, q25, [%0, #16 * 24]\n\t"
                         "ldp q26, q27, [%0, #16 * 26]\n\t"
                         "ldp q28, q29, [%0, #16 * 28]\n\t"
                         "ldp q30, q31, [%0, #16 * 30]\n\t"
                         "ldr w1, [%0, #16 * 32]\n\t"
                         "msr fpsr, x1\n\t"
                         "ldr w1, [%0, #16 * 32 + 4]\n"
                         "msr fpcr, x1\n\t" ::"r"(address)
                         : "x1", "memory");
}

void fpu_ptrace_getfpregs(void *fpregs, struct user_fpregs_struct *regs)
{
}

static slab_cache *fpu_cache = nullptr;

/**
 * @brief Initialize the FPU state slab cache
 *
 */
void fpu_init_cache()
{
    fpu_cache = kmem_cache_create("fpu-state", sizeof(fpstate), 16, 0, nullptr);
    if (!fpu_cache)
        panic("Out of memory allocating fpu state");
}

/**
 * @brief Allocate an FPU state object from the allocator
 *
 * @return Pointer to FPU state, or nullptr
 */
void *fpu_allocate_state()
{
    return kmem_cache_alloc(fpu_cache, 0);
}

/**
 * @brief Free FPU state object
 *
 * @param state Pointer to state
 */
void fpu_free_state(void *state)
{
    kmem_cache_free(fpu_cache, state);
}

void fpu_init()
{
    fpu_init_cache();
}

INIT_LEVEL_EARLY_PLATFORM_ENTRY(fpu_init);

size_t fpu_get_save_size()
{
    return sizeof(fpstate);
}

size_t fpu_get_save_alignment()
{
    return 16;
}
