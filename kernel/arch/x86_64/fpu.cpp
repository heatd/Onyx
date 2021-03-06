/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <onyx/compiler.h>		/* For USES_FANCY_* */
USES_FANCY_START
#include <immintrin.h>
#include <x86intrin.h>
USES_FANCY_END
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <onyx/fpu.h>
#include <onyx/x86/avx.h>
#include <onyx/x86/control_regs.h>

#include <sys/user.h>

bool avx_supported = false;

USES_FANCY_START

void do_xsave(void *address, long xcr0)
{
	_xsave(address, xcr0);
}

void do_fxsave(void *address)
{
	_fxsave(address);
}

void do_xrstor(void *address, long xcr0)
{
	_xrstor(address, xcr0);
}

void do_fxrstor(void *address)
{
	_fxrstor(address);
}

void do_ldmxcsr(unsigned int a)
{
	_mm_setcsr(a);
}

USES_FANCY_END

#define FXSAVE_AREA_SIZE         512
#define FXSAVE_AREA_ALIGNMENT    16

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
	if(avx_supported == true)
	{
		do_xsave(address, AVX_XCR0_FPU | AVX_XCR0_SSE | AVX_XCR0_AVX);
	}
	else
	{
		do_fxsave(address);
	}
}

void restore_fpu(void *address)
{
	if(avx_supported == true)
	{
		do_xrstor(address, AVX_XCR0_FPU | AVX_XCR0_SSE | AVX_XCR0_AVX);
	}
	else
	{
		do_fxrstor(address);
	}
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
	struct fpu_area *area = (struct fpu_area*) address;
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

void fpu_init(void)
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
