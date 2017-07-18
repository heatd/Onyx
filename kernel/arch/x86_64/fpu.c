/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <immintrin.h>
#include <x86intrin.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <kernel/fpu.h>
#include <kernel/avx.h>

#include <sys/user.h>
bool avx_supported = false;
void save_fpu(void *address)
{
	if(avx_supported == true)
	{
		_xsave(address, AVX_XCR0_FPU | AVX_XCR0_SSE | AVX_XCR0_AVX);
	}
	else
	{
		_fxsave(address);
	}
}
void restore_fpu(void *address)
{
	if(avx_supported == true)
	{
		_xrstor(address, AVX_XCR0_FPU | AVX_XCR0_SSE | AVX_XCR0_AVX);
	}
	else
	{
		_fxrstor(address);
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
	struct fpu_area *fpregs = __fpregs;
	regs->cwd = fpregs->fcw;
	regs->swd = fpregs->fsw;
	regs->ftw = fpregs->ftw;
	regs->fop = fpregs->fop;
	regs->rip = fpregs->fpu_ip;
	regs->rdp = fpregs->fpu_dp;
	regs->mxcsr = fpregs->mxcsr;
	regs->mxcr_mask = fpregs->mxcsr_mask;
	memcpy(regs->st_space, &regs->st_space, sizeof(regs->st_space) + sizeof(regs->xmm_space));
}
