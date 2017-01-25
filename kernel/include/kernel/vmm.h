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
#ifndef _VMM_H
#define _VMM_H

#include <stdint.h>
#include <stdlib.h>
#include <kernel/paging.h>

#if defined (__i386__)
	#define KERNEL_VIRTUAL_BASE 0xC0000000
#elif defined (__x86_64__)
	#define KERNEL_VIRTUAL_BASE 0xFFFFFFFF80000000
#endif

#define VM_TYPE_REGULAR		(0)
#define VM_TYPE_STACK 		(1)
#define VM_TYPE_SHARED 		(2)
#define VM_TYPE_HEAP 		(3)
#define VM_TYPE_HW 		(4)
#define VM_GLOBAL 		(0x2)
#define VM_USER 		(0x80)
#define VM_WRITE 		(0x1)
#define VM_NOEXEC 		(0x4)
#define VM_KERNEL 		(1)
#define VM_UPSIDEDOWN 		(2)
#define KERNEL_FB 		0xFFFFE00000000000
/* 
 * Deprecated and will be removed in a future date, after all code is ported. 
 * New code should use the new macros
*/
#define VMM_TYPE_REGULAR VM_TYPE_REGULAR
#define VMM_TYPE_STACK VM_TYPE_STACK
#define VMM_TYPE_SHARED VM_TYPE_SHARED
#define VMM_TYPE_HEAP VM_TYPE_HEAP
#define VMM_TYPE_HW VM_TYPE_HW
#define VMM_GLOBAL VM_GLOBAL
#define VMM_USER VM_USER
#define VMM_WRITE VM_WRITE
#define VMM_NOEXEC VM_NOEXEC

#define VM_HIGHER_HALF 0xFFFF800000000000
typedef struct ventry
{
	uintptr_t base;
	size_t pages;
	int rwx;
	int type;
} vmm_entry_t;
#ifndef __avl_tree_defined_
typedef struct avl_node
{
	uintptr_t key;
	uintptr_t end;
	vmm_entry_t *data;
	struct avl_node *left, *right;
} avl_node_t;
#define __avl_tree_defined_
#endif

void vmm_init();
void vmm_start_address_bookkeeping(uintptr_t framebuffer_address, uintptr_t heap);
void *vmm_allocate_virt_address(uint64_t flags, size_t pages, uint32_t type, uint64_t prot);
void *vmm_map_range(void* range, size_t pages, uint64_t flags);
void vmm_unmap_range(void *range, size_t pages);
void vmm_destroy_mappings(void *range, size_t pages);
void *vmm_reserve_address(void *addr, size_t pages, uint32_t type, uint64_t prot);
vmm_entry_t *vmm_is_mapped(void *addr);
PML4 *vmm_clone_as(avl_node_t **);
PML4 *vmm_fork_as(avl_node_t **);
void vmm_stop_spawning();
void vmm_change_perms(void *range, size_t pages, int perms);
void vmm_set_tree(avl_node_t *tree_);
avl_node_t *vmm_get_tree();
int vmm_check_pointer(void *addr, size_t needed_space);
inline size_t vmm_align_size_to_pages(size_t size)
{
	size_t pages = size / PAGE_SIZE;
	if(size % PAGE_SIZE)
		pages++;
	return pages;
}

void *vmalloc(size_t pages, int type, int perms);
#endif
