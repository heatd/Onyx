/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_X86_MSR_H
#define _ONYX_X86_MSR_H

#define IA32_APIC_BASE		0x0000001b
#define IA32_EFER		0xC0000080
#define FS_BASE_MSR 		0xC0000100
#define GS_BASE_MSR 		0xC0000101
#define KERNEL_GS_BASE 		0xC0000102
#define IA32_MSR_STAR 		0xC0000081
#define IA32_MSR_LSTAR 		0xC0000082
#define IA32_MSR_CSTAR 		0xC0000083
#define IA32_MSR_SFMASK 	0xC0000084
#define IA32_MSR_MC0_CTL 	0x00000400
#define IA32_MSR_PAT		0x00000277


/* Syscall/sysret enable */
#define IA32_EFER_SCE			(1 << 0)
/* Long mode enable */
#define IA32_EFER_LME			(1 << 8)
/* Long mode active */
#define IA32_EFER_LMA			(1 << 9)
/* No-execute enable */
#define IA32_EFER_NXE			(1 << 11)

#ifndef __ASSEMBLER__

#include <stdint.h>

inline void wrmsr(uint32_t msr, uint64_t val)
{
	uint32_t lo = (uint32_t) val;
	uint32_t hi = val >> 32;
	__asm__ __volatile__("wrmsr"::"a"(lo), "d"(hi), "c"(msr));
}

inline uint64_t rdmsr(uint32_t msr)
{
	uint32_t lo, hi;
	__asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));

	return (uint64_t) lo | ((uint64_t) hi << 32);
}

#endif

#endif
