/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/user.h>

#include <onyx/fpu.h>
#include <onyx/mm/slab.h>
#include <onyx/static_key.h>
#include <onyx/x86/avx.h>
#include <onyx/x86/control_regs.h>

DEFINE_STATIC_KEY_FALSE(avx_supported);

#define EDX_EAX(var) "d"((uint32_t) (var >> 32)), "a"((uint32_t) var)

void do_xsave(void *address, long xcr0)
{
    __asm__ __volatile__("xsave %0" : "+m"(*(unsigned long *) address) : EDX_EAX(xcr0) : "memory");
}

void do_fxsave(void *address)
{
    __asm__ __volatile__("fxsave %0" : "=m"(*(unsigned long *) address)::"memory");
}

void do_xrstor(void *address, long xcr0)
{
    __asm__ __volatile__("xrstor %0" ::"m"(*(unsigned long *) address), EDX_EAX(xcr0) : "memory");
}

void do_fxrstor(void *address)
{
    __asm__ __volatile__("fxrstor %0" ::"m"(*(unsigned long *) address) : "memory");
}

void do_ldmxcsr(unsigned int a)
{
    __asm__ __volatile__("ldmxcsr %0" ::"m"(a));
}

#define FXSAVE_AREA_SIZE      512
#define FXSAVE_AREA_ALIGNMENT 16

/* We're using these values by default. However, they may be overwritten by xsave code. */
size_t fpu_area_size = FXSAVE_AREA_SIZE;
size_t fpu_area_alignment = FXSAVE_AREA_ALIGNMENT;

size_t fpu_get_save_size(void)
{
    return fpu_area_size;
}

size_t fpu_get_save_alignment(void)
{
    return fpu_area_alignment;
}

void save_fpu(void *address)
{
    if (static_branch_likely(&avx_supported))
        do_xsave(address, AVX_XCR0_FPU | AVX_XCR0_SSE | AVX_XCR0_AVX);
    else
        do_fxsave(address);
}

void restore_fpu(void *address)
{
    if (static_branch_likely(&avx_supported))
        do_xrstor(address, AVX_XCR0_FPU | AVX_XCR0_SSE | AVX_XCR0_AVX);
    else
        do_fxrstor(address);
}

struct fpu_area
{
    uint16_t fcw;
    uint16_t fsw;
    uint8_t ftw;
    uint8_t res0;
    uint16_t fop;
    uint32_t fpu_ip;
    uint32_t fpu_cs;
    uint32_t fpu_dp;
    uint16_t ds;
    uint16_t res1;
    uint32_t mxcsr;
    uint32_t mxcsr_mask;
    uint8_t registers[0];
} __attribute__((packed));

void setup_fpu_area(unsigned char *address)
{
    struct fpu_area *area = (struct fpu_area *) address;
    area->mxcsr = 0x1F80;
}

void fpu_ptrace_getfpregs(void *__fpregs, struct user_fpregs_struct *regs)
{
    struct fpu_area *fpregs = (fpu_area *) __fpregs;
    regs->cwd = fpregs->fcw;
    regs->swd = fpregs->fsw;
    regs->ftw = fpregs->ftw;
    regs->fop = fpregs->fop;
    regs->rip = fpregs->fpu_ip;
    regs->rdp = fpregs->fpu_dp;
    regs->mxcsr = fpregs->mxcsr;
    regs->mxcr_mask = fpregs->mxcsr_mask;
    memcpy(regs->st_space, &fpregs->registers, sizeof(regs->st_space) + sizeof(regs->xmm_space));
}

static slab_cache *fpu_cache = nullptr;

/**
 * @brief Initialize the FPU state slab cache
 *
 */
void fpu_init_cache()
{
    if (fpu_cache)
        return;
    fpu_cache = kmem_cache_create("fpu-state", fpu_area_size, fpu_area_alignment, 0, nullptr);
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
    /* We are initializing the FPU as recommended in 9.2.1 of the
     * software programming guide
     */
    unsigned long cr0 = x86_read_cr0();

    cr0 &= ~CR0_EM;
    cr0 |= CR0_MP | CR0_NE;

    x86_write_cr0(cr0);

    unsigned long cr4 = x86_read_cr4();
    cr4 |= CR4_OSFXSR | CR4_OSXMMEXCPT;

    x86_write_cr4(cr4);
    do_ldmxcsr(0x1F80);
}
