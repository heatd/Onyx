/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _KERNEL_CPU_H
#define _KERNEL_CPU_H
#include <stdint.h>

#define CPUID_MANUFACTURERID 		0
#define CPUID_MAXFUNCTIONSUPPORTED 	0x80000000
#define CPUID_BRAND0			0x80000002
#define CPUID_BRAND1 			0x80000003
#define CPUID_BRAND2 			0x80000004
#define CPUID_ASS			0x80000008 // Address space size (ASS for short :P)
#define CPUID_SIGN   			0x1
#define CPUID_FEATURES			1
#define CPUID_FEATURE_ECX_AVX		(1 << 28)
#define CPUID_FEATURE_ECX_XSAVE		(1 << 26)
typedef struct cpu
{
	char manuid[13];
	char brandstr[48];
	uint32_t max_function;
	uint32_t stepping, family, model, extended_model, extended_family;
	int virtualAddressSpace, physicalAddressSpace;
	/* Add more as needed */
} cpu_t;

struct processor
{
#if defined (__x86_64__)
	volatile char *lapic;
	struct processor *self;
	void *kernel_stack;
	void *scratch_rsp_stack;
	volatile char *lapic_phys;
	int cpu_num;
	int lapic_id;
	size_t apic_ticks;
#else
#error "Implement this structure for your architecture"
#endif
	size_t sched_quantum;
};

void cpu_identify();
void cpu_init_interrupts();
int cpu_init_mp();

__attribute__((always_inline))
inline struct processor *get_gs_data()
{
	struct processor *proc;
	__asm__ __volatile__("movq %%gs:0x8, %0":"=r"(proc));
	return proc;
}

#define DISABLE_INTERRUPTS() __asm__ __volatile__("cli")
#define ENABLE_INTERRUPTS() __asm__ __volatile__("sti")
#endif
