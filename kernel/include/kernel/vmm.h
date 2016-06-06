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
#ifndef _VMM_H
#define _VMM_H

#if defined (__i386__)
	#define KERNEL_VIRTUAL_BASE 0xC0000000
#elif defined (__x86_64__)
	#define KERNEL_VIRTUAL_BASE 0xFFFFFFFF80000000
#endif
#include <stdint.h>
#include <stdlib.h>
typedef struct ventry
{
	uintptr_t baseAddress;
	size_t size;
	size_t sizeInPages;
	int rw;
	int nx;
	struct ventry* next;
} VasEntry;
#define VM_KERNEL (1)
#define VM_UPSIDEDOWN (2)
void vmm_init();
void StartAddressBookkeeping(uintptr_t framebufferAddress);
void* AllocateVirtAddress(uint64_t flags, size_t pages);
void* vmm_map_range(void* range, size_t pages);



#endif
