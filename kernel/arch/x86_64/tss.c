/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <string.h>

#include <kernel/tss.h>
#include <kernel/vmm.h>
#include <kernel/cpu.h>
#include <kernel/compiler.h>
#include <kernel/panic.h>
extern tss_entry_t tss;
extern void tss_flush();
extern int tss_gdt;
void init_tss()
{
	memset(&tss, 0, sizeof(tss_entry_t));
	/* Easier to do bit manipulation with different pointer sizes */
	uint8_t *tss_gdtb = (uint8_t*)((uint64_t) &tss_gdt + 0xFFFFFFFF80000000);
	uint16_t *tss_gdtw = (uint16_t*)((uint64_t) &tss_gdt + 0xFFFFFFFF80000000);
	uint32_t *tss_gdtd = (uint32_t*)((uint64_t) &tss_gdt + 0xFFFFFFFF80000000);
	tss_gdtw[1] = (uintptr_t) &tss & 0xFFFF;
	tss_gdtb[4] = ((uintptr_t) &tss >> 16) & 0xFF;
	tss_gdtb[6] = ((uintptr_t) &tss >> 24) & 0xFF;
	tss_gdtb[7] = ((uintptr_t) &tss >> 24) & 0xFF;
	tss_gdtd[2] = ((uintptr_t) &tss >> 32);
	tss_flush();
}
void set_kernel_stack(uintptr_t stack0)
{
	struct processor *proc = get_processor_data();
	if(unlikely(!proc))
	{
		tss.stack0 = stack0;
		tss.ist[0] = stack0;
	}
	else
	{
		tss_entry_t *entry = proc->tss;
		entry->stack0 = stack0;
		entry->ist[0] = stack0;
	}
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
	tss_gdtb[4] = ((uintptr_t) &new_tss >> 16) & 0xFF;
	tss_gdtb[6] = ((uintptr_t) &new_tss >> 24) & 0xFF;
	tss_gdtb[7] = ((uintptr_t) &new_tss >> 24) & 0xFF;
	tss_gdtd[2] = ((uintptr_t) &new_tss >> 32);
	tss_flush();

	get_processor_data()->tss = new_tss;
}
