/*
 * Copyright (c) 2017 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <cpuid.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <onyx/cpu.h>
#include <onyx/panic.h>
#include <onyx/registers.h>
#include <onyx/x86/mce.h>
#include <onyx/x86/msr.h>

void dump_interrupt_context(struct registers *ctx);

void do_machine_check(struct registers *ctx)
{
    union {
        struct
        {
            uint32_t low;
            uint32_t high;
        } u_hilo;
        uint64_t value;
    } mc0;

    mc0.value = rdmsr(IA32_MSR_MC0_CTL);

    dump_interrupt_context(ctx);

    printk("Machine check info: Bank 0: %08x\n", (uint32_t) mc0.value);

    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;

    if (!__get_cpuid(CPUID_SIGN, &eax, &ebx, &ecx, &edx))
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
    if (family == 6 || family == 15)
        cpu_model = model + (extended_model << 4);
    if (family == 15)
        cpu_family = family + extended_family;

    printk("CPUID: %04x:%04x:%04x:%04x\n", cpu_model, cpu_family, stepping, processor_type);

    panic("mce");
}
