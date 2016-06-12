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
#define VMM_TYPE_REGULAR 0
#define VMM_TYPE_STACK 1
#define VMM_TYPE_SHARED 2
#define VMM_TYPE_HEAP 3
#define VMM_TYPE_HW 4
#define VMM_READ 0x5
#define VMM_WRITE 0x4
#define VMM_EXEC 0x1
#define VMM_RW (VMM_READ | VMM_WRITE)
#define VMM_RX (VMM_READ | VM_EXEC)
#define VMM_RWX (VMM_READ | VMM_EXEC | VMM_WRITE)
typedef struct ventry
{
	uintptr_t base;
	size_t pages;
	int rwx;
	int type;
} vmm_entry_t;
#define VM_KERNEL (1)
#define VM_UPSIDEDOWN (2)
#define PAGE_SIZE 4096
void vmm_init();
void vmm_start_address_bookeeping(uintptr_t framebuffer_address);
void *vmm_allocate_virt_address(uint64_t flags, size_t pages, uint32_t type);
void *vmm_map_range(void* range, size_t pages, uint64_t flags);
void *vmm_reserve_address(void *addr, size_t pages, uint32_t type);


#endif
