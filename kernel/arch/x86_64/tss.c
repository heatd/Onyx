/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
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
extern tss_entry_t tss;
extern void tss_flush();
void init_tss()
{
	printf("tss: %x\n",&tss);
	tss.stack0 = (uint64_t)AllocateVirtAddress(VM_KERNEL, 2);
	vmm_map_range((void*)tss.stack0, 2);
	tss.ist[0] = tss.stack0;
	tss_flush();
}
