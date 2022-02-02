/*
 * Copyright (c) 2017 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <cpuid.h>
#include <stdint.h>
#include <stdio.h>

#include <onyx/cpu.h>
#include <onyx/fpu.h>
#include <onyx/x86/avx.h>
#include <onyx/x86/control_regs.h>

static inline void xsetbv(unsigned long r, unsigned long xcr0)
{
    __asm__ __volatile__("xsetbv" ::"c"(r), "a"(xcr0 & 0xffffffff), "d"(xcr0 >> 32));
}

static inline unsigned long xgetbv(unsigned long r)
{
    unsigned long ret = 0;
    __asm__ __volatile__("xgetbv" : "=A"(ret) : "c"(r));
    return ret;
}

extern size_t fpu_area_size;
extern size_t fpu_area_alignment;

void avx_init(void)
{
    if (x86_has_cap(X86_FEATURE_XSAVE))
    {
        x86_write_cr4(x86_read_cr4() | CR4_OSXSAVE);
    }

    if (x86_has_cap(X86_FEATURE_AVX) && x86_has_cap(X86_FEATURE_XSAVE))
    {
        /* If it's supported, set the proper xcr0 bits */
        int64_t xcr0 = 0;

        xcr0 |= AVX_XCR0_AVX | AVX_XCR0_FPU | AVX_XCR0_SSE;

        xsetbv(0, xcr0);

        uint32_t eax, ebx, ecx, edx;

        ecx = 0;
        if (!__get_cpuid_count(CPUID_XSTATE, 0, &eax, &ebx, &ecx, &edx))
            return;

        fpu_area_size = ebx;
        fpu_area_alignment = AVX_SAVE_ALIGNMENT;

        avx_supported = true;
    }
}
