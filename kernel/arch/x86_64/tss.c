/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <string.h>

#include <onyx/tss.h>
#include <onyx/vmm.h>
#include <onyx/cpu.h>
#include <onyx/compiler.h>
#include <onyx/panic.h>
#include <onyx/gdt.h>

extern tss_entry_t tss;
extern void tss_flush();
extern int tss_gdt;
void init_tss()
{
	gdt_init_percpu();
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
	tss_gdtb[4] = ((uintptr_t) new_tss >> 16) & 0xFF;
	tss_gdtb[6] = ((uintptr_t) new_tss >> 24) & 0xFF;
	tss_gdtb[7] = ((uintptr_t) new_tss >> 24) & 0xFF;
	tss_gdtd[2] = ((uintptr_t) new_tss >> 32);
	tss_flush();

	/* Note that we use get_processor_data_inl() here, because get_processor_data() returns NULL as
	   percpu_initialized isn't true yet! get_processor_data_inl() makes no such checks!
	*/
	get_processor_data_inl()->tss = new_tss;
}
