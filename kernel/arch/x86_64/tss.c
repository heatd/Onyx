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
#include <kernel/tss.h>
#include <kernel/vmm.h>
#include <stdio.h>
#include <string.h>
extern tss_entry_t tss;
extern void tss_flush();
extern int tss_gdt;
void init_tss()
{
	printf("tss: %x\n",&tss);
	memset(&tss, 0, sizeof(tss_entry_t));
	/* Easier to do bit manipulation with different pointer sizes */
	uint8_t *tss_gdtb = (uint8_t*)((uint64_t)&tss_gdt + 0xFFFFFFFF80000000);
	uint16_t *tss_gdtw = (uint16_t*)((uint64_t)&tss_gdt + 0xFFFFFFFF80000000);
	uint32_t *tss_gdtd = (uint32_t*)((uint64_t)&tss_gdt + 0xFFFFFFFF80000000);
	tss_gdtw[1] = (uintptr_t)&tss & 0xFFFF;
	tss_gdtb[4] = ((uintptr_t)&tss >> 16) & 0xFF;
	tss_gdtb[6] = ((uintptr_t)&tss >> 24) & 0xFF;
	tss_gdtb[7] = ((uintptr_t)&tss >> 24) & 0xFF;
	tss_gdtd[2] = ((uintptr_t)&tss >> 32);
	tss_flush();
}
int is_dbg_tss = 0;
void set_kernel_stack(uintptr_t stack0)
{
	tss.stack0 = stack0;
	tss.ist[0] = stack0;
}
