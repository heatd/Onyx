/*
 * Copyright (c) 2016 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <string.h>

#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/init.h>
#include <onyx/panic.h>
#include <onyx/tss.h>
#include <onyx/vm.h>
#include <onyx/x86/gdt.h>

extern "C" void tss_flush();

void tss_init(void)
{
    gdt_init_percpu();
}

INIT_LEVEL_EARLY_PLATFORM_ENTRY(tss_init);

PER_CPU_VAR(tss_entry_t *tss);

void set_kernel_stack(uintptr_t stack0)
{
    tss_entry_t *entry = get_per_cpu(tss);
    entry->stack0 = stack0;
    entry->ist[0] = stack0;
}

unsigned char double_fault_stack[2048];
unsigned char *double_fault_stack_top = &double_fault_stack[2047];

void init_percpu_tss(uint64_t *gdt)
{
    tss_entry_t *new_tss = new tss_entry_t;
    if (!new_tss)
    {
        panic("Out of memory allocating a per-cpu TSS");
    }

    memset(new_tss, 0, sizeof(tss_entry_t));
    uint32_t tss_limit = sizeof(tss_entry_t) - 1;

    union tss_descriptor *desc = (union tss_descriptor *)&gdt[7];
    memset(desc, 0, sizeof(*desc));

    uintptr_t tss_addr = (uintptr_t)new_tss;
    desc->type = TSS_TYPE_INACTIVE | TSS_TYPE_DPL(3) | TSS_TYPE_PRESENT;
    desc->base_low = (uint16_t)tss_addr;
    desc->base_16_23 = tss_addr >> 16;
    desc->base_mid = tss_addr >> 24;
    desc->base_high = tss_addr >> 32;
    desc->limit_low = tss_limit;
    desc->limit_flags = tss_limit >> 16;
    desc->reserved = 0;

    tss_flush();

    write_per_cpu(tss, new_tss);

    new_tss->ist[1] = (unsigned long)double_fault_stack_top;
}
