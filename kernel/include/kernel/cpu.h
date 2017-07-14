/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_CPU_H
#define _KERNEL_CPU_H

#include <stdint.h>

#include <kernel/acpi.h>
#include <kernel/scheduler.h>
#ifdef __x86_64__
#include <kernel/tss.h>
#endif

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
	struct acpi_processor *acpi_processor;
	tss_entry_t *tss;
#else
#error "Implement this structure for your architecture"
#endif
	size_t sched_quantum;
	thread_t *current_thread;
};

void cpu_identify(void);
void cpu_init_interrupts(void);
int cpu_init_mp(void);
int get_nr_cpus(void);
struct processor *get_processor_data(void);
#ifdef __x86_64__
static inline struct processor *get_processor_data_inl(void)
{
	struct processor *proc;
	__asm__ __volatile__("movq %%gs:0x8, %0":"=r"(proc));
	return proc;
}
#define DISABLE_INTERRUPTS() __asm__ __volatile__("cli")
#define ENABLE_INTERRUPTS() __asm__ __volatile__("sti")
#endif
static inline uintptr_t cpu_get_cr0(void)
{
	uintptr_t cr0;
	__asm__ __volatile__("mov %%cr0, %0":"=r"(cr0));
	return cr0;
}
static inline uintptr_t cpu_get_cr2(void)
{
	uintptr_t cr2;
	__asm__ __volatile__("mov %%cr2, %0":"=r"(cr2));
	return cr2;
}
static inline uintptr_t cpu_get_cr3(void)
{
	uintptr_t cr3;
	__asm__ __volatile__("movq %%cr3, %%rax\t\nmovq %%rax, %0":"=r"(cr3));
	return cr3;
}
static inline uintptr_t cpu_get_cr4(void)
{
	uintptr_t cr4;
	__asm__ __volatile__("mov %%cr4, %0":"=r"(cr4));
	return cr4;
}
#endif
