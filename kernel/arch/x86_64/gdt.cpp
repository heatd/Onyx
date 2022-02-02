/*
 * Copyright (c) 2017 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
#include <string.h>

#include <onyx/panic.h>
#include <onyx/tss.h>
#include <onyx/vm.h>
#include <onyx/x86/gdt.h>

extern unsigned char gdt_begin;
extern unsigned char gdt_end;

uint16_t gdt_get_size()
{
    return &gdt_end - &gdt_begin;
}

extern gdtr_t gdtr3;
extern "C" void gdt_flush(gdtr_t *gdtr);

void gdt_init_percpu(void)
{
    uint16_t size = gdt_get_size();
    /* Create another copy of the gdt */
    uint64_t *gdt = reinterpret_cast<uint64_t *>(malloc(size));
    if (!gdt)
    {
        panic("Out of memory while allocating a percpu GDT");
    }

    gdtr_t gdtr;

    gdtr_t *g = (gdtr_t *)PHYS_TO_VIRT(&gdtr3);
    /* Copy the gdt */
    memcpy(gdt, (const void *)g->ptr, size);

    /* Setup the GDTR */
    gdtr.size = size - 1;
    gdtr.ptr = (uint64_t)gdt;

    /* Flush the GDT */
    gdt_flush(&gdtr);

    init_percpu_tss(gdt);
}
