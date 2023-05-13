/*
 * Copyright (c) 2019 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_X86_CONTROL_REGS_H
#define _ONYX_X86_CONTROL_REGS_H

/* Protection enable */
#define CR0_PE  (1 << 0)
/* Monitor Coprocessor */
#define CR0_MP  (1 << 1)
/* Emulation */
#define CR0_EM  (1 << 2)
/* Task switched */
#define CR0_TS  (1 << 3)
/* Extension type - harcoded to 1 since P6 */
#define CR0_ET  (1 << 4)
/* Numeric error */
#define CR0_NE  (1 << 5)
/* Write protect */
#define CR0_WP  (1 << 16)
/* Alignment Mask*/
#define CR0_AM  (1 << 18)
/* Not write-through */
#define CR0_NWT (1 << 29)
/* Cache disable */
#define CR0_CD  (1 << 30)
/* Paging */
#define CR0_PG  (1U << 31)

/* Virtual-8086 mode extensions */
#define CR4_VME        (1 << 0)
/* Protected mode virtual interrupts */
#define CR4_PVI        (1 << 1)
/* Time stamp disable - restricts rdtsc/rdtscp to the kernel-mode */
#define CR4_TSD        (1 << 2)
/* Debugging extensions */
#define CR4_DE         (1 << 3)
/* Page size extensions */
#define CR4_PSE        (1 << 4)
/* Physical address extension */
#define CR4_PAE        (1 << 5)
/* Machine check enable */
#define CR4_MCE        (1 << 6)
/* Page global enable */
#define CR4_PGE        (1 << 7)
/* Performance monitoring counter enable */
#define CR4_PCE        (1 << 8)
/* OS support for fxsave and fxrstor */
#define CR4_OSFXSR     (1 << 9)
/* OS support for unmask SIMD floating point exceptions */
#define CR4_OSXMMEXCPT (1 << 10)
/* User mode instruction prevention */
#define CR4_UMIP       (1 << 11)
/* Linear address 57-bit enable (LA57) - PML5 */
#define CR4_LA57       (1 << 12)
/* VMX enable */
#define CR4_VMXE       (1 << 13)
/* SMX enable */
#define CR4_SMXE       (1 << 14)
/* FSGSBASE enable*/
#define CR4_FSGSBASE   (1 << 16)
/* PCID enable */
#define CR4_PCIDE      (1 << 17)
/* XSAVE and processor extended states enable */
#define CR4_OSXSAVE    (1 << 18)
/* SMEP enable */
#define CR4_SMEP       (1 << 20)
/* SMAP enable */
#define CR4_SMAP       (1 << 21)
/* Protection key enable */
#define CR4_PKE        (1 << 22)

#ifndef __ASSEMBLER__

static inline unsigned long x86_read_cr0()
{
    unsigned long val;
    __asm__ __volatile__("mov %%cr0, %0" : "=r"(val));
    return val;
}

static inline unsigned long x86_read_cr2()
{
    unsigned long val;
    __asm__ __volatile__("mov %%cr2, %0" : "=r"(val));
    return val;
}

static inline unsigned long x86_read_cr3()
{
    unsigned long val;
    __asm__ __volatile__("mov %%cr3, %0" : "=r"(val));
    return val;
}

static inline unsigned long x86_read_cr4()
{
    unsigned long val;
    __asm__ __volatile__("mov %%cr4, %0" : "=r"(val));
    return val;
}

static inline void x86_write_cr0(unsigned long val)
{
    __asm__ __volatile__("mov %0, %%cr0" ::"r"(val));
}

static inline void x86_write_cr2(unsigned long val)
{
    __asm__ __volatile__("mov %0, %%cr2" ::"r"(val));
}

static inline void x86_write_cr3(unsigned long val)
{
    __asm__ __volatile__("mov %0, %%cr3" ::"r"(val));
}

static inline void x86_write_cr4(unsigned long val)
{
    __asm__ __volatile__("mov %0, %%cr4" ::"r"(val));
}

#endif

#endif
