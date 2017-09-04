/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

#include <kernel/log.h>
#include <kernel/vfs.h>
#include <kernel/vmm.h>
#include <kernel/vdso.h>

#define VDSO_NAME "/usr/lib/onyx-vdso.so.0"
static _Bool has_vdso = false;
static void *vdso_mem = NULL;
static size_t vdso_size = 0;
void init_vdso(void)
{
	/* Try to find the VDSO */
	struct inode *file = open_vfs(fs_root, VDSO_NAME);
	/* If we can't find it, assume we don't have one */
	if(file)
	{
		INFO("vdso", "kernel has vdso!\nvdso: name: %s\n", VDSO_NAME);
		has_vdso = true;
	}
	else return;

	/* Allocate a buffer of page aligned memory */
	vdso_mem = vmalloc(vmm_align_size_to_pages(file->size), VM_TYPE_REGULAR, VM_KERNEL | VM_WRITE);
	if(!vdso_mem)
	{
		ERROR("vdso", "error while allocating memory: %s\n", strerror(errno));
		has_vdso = false;
		close_vfs(file);
		return;
	}

	/* Read the file */
	if(file->size != read_vfs(0, 0, file->size, vdso_mem, file))
	{
		ERROR("vdso", "error while reading the vdso file: %s\n", strerror(errno));
		vfree(vdso_mem, vmm_align_size_to_pages(file->size));
		has_vdso = false;
		close_vfs(file);
		return;
	}
	vdso_size = vmm_align_size_to_pages(file->size) * PAGE_SIZE;
}
void *map_vdso(void)
{
	/* If there's no VDSO, just return silently */
	if(has_vdso == false)
		return NULL;
	
	void *vdso_address = vmm_allocate_virt_address(VM_ADDRESS_USER, vdso_size / PAGE_SIZE,
			     VM_TYPE_SHARED, VM_WRITE | VM_USER, 0);
	if(!vdso_address)
		return NULL;
	for(size_t i = 0; i < vdso_size; i += PAGE_SIZE)
	{
		paging_map_phys_to_virt((uint64_t) vdso_address + i, (uint64_t) virtual2phys((void*) 
		((uintptr_t) vdso_address + i)), VM_WRITE);
	}
	return vdso_address;
}
