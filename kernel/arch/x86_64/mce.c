/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <cpuid.h>

#include <onyx/registers.h>
#include <onyx/x86/mce.h>
#include <onyx/x86/msr.h>
#include <onyx/cpu.h>
#include <onyx/panic.h>

void dump_interrupt_context(intctx_t *ctx);

void do_machine_check(intctx_t *ctx)
{
	union
	{
		struct
		{
			uint32_t low;
			uint32_t high;
		} u_hilo;
		uint64_t value;
	} mc0;

	rdmsr(IA32_MSR_MC0_CTL, &mc0.u_hilo.low, &mc0.u_hilo.high);

	dump_interrupt_context(ctx);

	printk("Machine check info: Bank 0: %08x\n", (uint32_t) mc0.value);

	uint32_t eax = 0;
	uint32_t ebx = 0;
	uint32_t ecx = 0;
	uint32_t edx = 0;
	if(!__get_cpuid(CPUID_SIGN, &eax, &ebx, &ecx, &edx))
	{
		panic("Couldn't get CPU signature through cpuid\n");
	}

	unsigned int stepping = eax & 0xf;
	unsigned int model = (eax >> 4) & 0xf;
	unsigned int family = (eax >> 8) & 0xf;
	unsigned int processor_type = (eax >> 12) & 0x3;
	unsigned int extended_model = (eax >> 16) & 0xf;
	unsigned int extended_family = (eax >> 20) & 0xff;

	unsigned int cpu_family = family;
	unsigned int cpu_model = model;
	if(family == 6 || family == 15)
		cpu_model = model + (extended_model << 4);
	if(family == 15)
		cpu_family = family + extended_family;
	
	printk("CPUID: %04x:%04x:%04x:%04x\n", cpu_model, cpu_family, stepping,
		processor_type);

	panic("mce");
}

