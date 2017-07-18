/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <cpuid.h>
#include <stdio.h>
#include <immintrin.h>
#include <x86intrin.h>

#include <kernel/avx.h>
#include <kernel/fpu.h>
#include <kernel/cpu.h>

static inline void xsetbv(unsigned long r, unsigned long xcr0)
{
	__asm__ __volatile__("xsetbv"::"c"(r), "A"(xcr0));
}
static inline unsigned long xgetbv(unsigned long r)
{
	unsigned long ret = 0;
	__asm__ __volatile__("xgetbv":"=A"(ret):"c"(r));
	return ret;
}
void avx_init(void)
{
	if(x86_has_cap(X86_FEATURE_AVX) && x86_has_cap(X86_FEATURE_XSAVE))
	{
		avx_supported = true;
		/* If it's supported, set the proper xcr0 bits */
		int64_t xcr0 = xgetbv(0);

		xcr0 |= AVX_XCR0_AVX | AVX_XCR0_FPU | AVX_XCR0_SSE;

		xsetbv(0, xcr0);
	}
}
