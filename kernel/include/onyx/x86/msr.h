/*
 * Copyright (c) 2017 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_X86_MSR_H
#define _ONYX_X86_MSR_H

#define IA32_APIC_BASE    0x0000001b
#define IA32_EFER         0xC0000080
#define FS_BASE_MSR       0xC0000100
#define GS_BASE_MSR       0xC0000101
#define KERNEL_GS_BASE    0xC0000102
#define IA32_MSR_STAR     0xC0000081
#define IA32_MSR_LSTAR    0xC0000082
#define IA32_MSR_CSTAR    0xC0000083
#define IA32_MSR_SFMASK   0xC0000084
#define IA32_MSR_MC0_CTL  0x00000400
#define IA32_MSR_PAT      0x00000277
#define IA32_TSC_DEADLINE 0x000006e0
#define IA32_MISC_ENABLE  0x000001a0
#define IA32_X2APIC_BASE  0x00000800

#define IA32_MISC_ENABLE_FAST_STRINGS_ENABLE      (1 << 0)
#define IA32_MISC_ENABLE_AUTO_TCC_ENABLE          (1 << 3)
#define IA32_MISC_ENABLE_PM_AVAIALBLE             (1 << 7)
#define IA32_MISC_ENABLE_BTS_STORAGE_UNAVAILABLE  (1 << 11)
#define IA32_MISC_ENABLE_PEBS_UNAVAILABLE         (1 << 12)
#define IA32_MISC_ENABLE_ENHANCED_INTEL_SPEEDSTEP (1 << 16)
#define IA32_MISC_ENABLE_ENABLE_MONITOR_FSM       (1 << 18)
#define IA32_MISC_ENABLE_LIMIT_CPUID_MAXVAL       (1 << 22)
#define IA32_MISC_ENABLE_XTPR_MSG_DISABLE         (1 << 23)
#define IA32_MISC_ENABLE_XD_BIT_DISABLE           (1UL << 34)

/* Syscall/sysret enable */
#define IA32_EFER_SCE (1 << 0)
/* Long mode enable */
#define IA32_EFER_LME (1 << 8)
/* Long mode active */
#define IA32_EFER_LMA (1 << 9)
/* No-execute enable */
#define IA32_EFER_NXE (1 << 11)

#ifndef __ASSEMBLER__

#include <stdint.h>

static inline void wrmsr(uint32_t msr, uint64_t val)
{
    uint32_t lo = (uint32_t) val;
    uint32_t hi = val >> 32;
    __asm__ __volatile__("wrmsr" ::"a"(lo), "d"(hi), "c"(msr) : "memory");
}

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));

    return (uint64_t) lo | ((uint64_t) hi << 32);
}

#endif

#endif
