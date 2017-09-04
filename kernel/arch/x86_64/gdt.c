/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <string.h>

#include <onyx/panic.h>
#include <onyx/gdt.h>
#include <onyx/tss.h>

#define GDT_SIZE 77
extern gdtr_t gdtr3;
extern void gdt_flush(gdtr_t *gdtr);
void gdt_init_percpu(void)
{
	/* Create another copy of the gdt */
	uint64_t *gdt = malloc(GDT_SIZE);
	if(!gdt)
		halt();
	/* Create a gdtr */
	gdtr_t *gdtr = malloc(sizeof(gdtr_t));
	if(!gdtr)
	{
		free(gdt);
		panic("Out of memory while allocating a percpu GDT\n");
	}
	/* Copy the gdt */
	memcpy(gdt, (const void*) gdtr3.ptr, GDT_SIZE);

	/* Setup the GDTR */
	gdtr->size = GDT_SIZE - 1;
	gdtr->ptr = (uint64_t) gdt;

	/* Flush the GDT */
	gdt_flush(gdtr);

	init_percpu_tss(gdt);
}
