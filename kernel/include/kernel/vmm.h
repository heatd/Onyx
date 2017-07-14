/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _VMM_H
#define _VMM_H

#include <stdint.h>
#include <stdlib.h>

#include <kernel/paging.h>
#include <kernel/avl.h>

#include <sys/types.h>
#if defined (__i386__)
	#define KERNEL_VIRTUAL_BASE 0xC0000000
#elif defined (__x86_64__)
	#define KERNEL_VIRTUAL_BASE 0xFFFFFFFF80000000
#endif

#define CONFIG_ASLR		1

#define VM_TYPE_REGULAR		(0)
#define VM_TYPE_STACK 		(1)
#define VM_TYPE_SHARED 		(2)
#define VM_TYPE_HEAP 		(3)
#define VM_TYPE_HW 		(4)
#define VM_TYPE_FILE_BACKED	(5)
#define VM_GLOBAL 		(0x2)
#define VM_USER 		(0x80)
#define VM_WRITE 		(0x1)
#define VM_NOEXEC 		(0x4)
#define VM_ADDRESS_USER		(0)
#define VM_KERNEL 		(1)
#define VM_COW			(1 << 1)
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
#define PHYS_TO_VIRT(x) (void*)((uintptr_t) x + PHYS_BASE)
typedef struct ventry
{
	uintptr_t base;
	size_t pages;
	int rwx;
	int type;
	int mapping_type;
	int fd;
	off_t offset;
	int flags;
} vmm_entry_t;

struct fault_info
{
	uintptr_t fault_address;
	_Bool write;
	_Bool read;
	_Bool exec;
	_Bool user;
};
void vmm_init();
void vmm_start_address_bookkeeping(uintptr_t framebuffer_address, uintptr_t heap);
void *vmm_allocate_virt_address(uint64_t flags, size_t pages, uint32_t type, uint64_t prot, uintptr_t alignment);
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
void *vmalloc(size_t pages, int type, int perms);
void vfree(void *ptr, size_t pages);
void vmm_print_stats(void);
int vmm_handle_page_fault(vmm_entry_t *entry, struct fault_info *info);
void *vmalloc(size_t pages, int type, int perms);
void vmm_print_stats(void);
void *dma_map_range(void *phys, size_t size, size_t flags);
void vmm_destroy_addr_space(avl_node_t *tree);
int vm_sanitize_address(void *address, size_t pages);
void *vmm_gen_mmap_base(void);
void *vmm_gen_brk_base(void);
void vmm_sysfs_init(void);
int vmm_mark_cow(vmm_entry_t *zone);
static inline size_t vmm_align_size_to_pages(size_t size)
{
	size_t pages = size / PAGE_SIZE;
	if(size % PAGE_SIZE)
		pages++;
	return pages;
}
static inline ssize_t copy_to_user(void *usr, void *data, size_t len)
{
	if(vmm_check_pointer(usr, len) < 0)
		return -len;
	memcpy(usr, data, len);
	return len;
}
static inline ssize_t copy_from_user(void *usr, void *data, size_t len)
{
	if(vmm_check_pointer(usr, len) < 0)
		return -len;
	memcpy(data, usr, len);
	return len;
}

#endif
