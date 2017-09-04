/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_GDT_H
#define _KERNEL_GDT_H

#include <stdint.h>

typedef struct
{
	uint16_t size;
	uint64_t ptr;
} __attribute__((packed)) gdtr_t;

void gdt_init_percpu(void);
#endif
