/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _X86_VM_H
#define _X86_VM_H

/* x86_64 virtual address space layout. Subsystem addresses are *offsets*, 
 * not absolute addresses
*/

typedef enum
{
	arch_low_half_min  	= 0x400000,
	arch_brk_base		= 0x80000000,
	arch_mmap_base		= 0x0000550000000000,
	arch_low_half_max  	= 0x00007fffffffffff,
	arch_high_half		= 0xffff800000000000,	/* Default to this, but don't assume it */
	arch_vmalloc_off 	= 0x000000000000,
	arch_kstacks_off  	= 0x100000000000,
	arch_heap_off		= 0x200000000000,
} vas_areas;

#define VMALLOC_ASLR_BITS	40
#define KSTACKS_ASLR_BITS	40
#define HEAP_ASLR_BITS		40
#define MMAP_ASLR_BITS		42
#define BRK_ASLR_BITS		30

#endif
