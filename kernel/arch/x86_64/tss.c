/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <string.h>

#include <onyx/tss.h>
#include <onyx/vm.h>
#include <onyx/cpu.h>
#include <onyx/compiler.h>
#include <onyx/panic.h>
#include <onyx/gdt.h>
#include <onyx/init.h>

extern void tss_flush();
extern int tss_gdt;

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

void init_percpu_tss(uint64_t *gdt)
{
	tss_entry_t *new_tss = malloc(sizeof(tss_entry_t));
	if(!new_tss)
		halt();
	memset(new_tss, 0, sizeof(tss_entry_t));

	uint8_t *tss_gdtb = (uint8_t*) &gdt[7];
	uint16_t *tss_gdtw = (uint16_t*) &gdt[7];
	uint32_t *tss_gdtd = (uint32_t*) &gdt[7];
	tss_gdtw[1] = (uintptr_t) new_tss & 0xFFFF;
	tss_gdtb[4] = ((uintptr_t) new_tss >> 16) & 0xFF;
	tss_gdtb[6] = ((uintptr_t) new_tss >> 24) & 0xFF;
	tss_gdtb[7] = ((uintptr_t) new_tss >> 24) & 0xFF;
	tss_gdtd[2] = ((uintptr_t) new_tss >> 32);
	tss_flush();

	write_per_cpu(tss, new_tss);
}
