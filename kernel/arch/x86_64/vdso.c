/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

#include <onyx/log.h>
#include <onyx/vfs.h>
#include <onyx/vmm.h>
#include <onyx/vdso.h>

extern char __vdso_start;
extern size_t __vdso_size;

void *map_vdso(void)
{
	uintptr_t vdso = (uintptr_t) &__vdso_start;
	size_t vdso_size = (size_t) &__vdso_size;
#ifdef CONFIG_NO_VDSO
	return NULL;
#else
	void *vdso_address = vmm_allocate_virt_address(VM_ADDRESS_USER, vdso_size / PAGE_SIZE,
			     VM_TYPE_SHARED, VM_WRITE | VM_USER, 0);
	if(!vdso_address)
		return NULL;
	for(size_t i = 0; i < vdso_size; i += PAGE_SIZE)
	{
		paging_map_phys_to_virt((uint64_t) vdso_address + i, vdso + i, VM_WRITE);
	}
	return vdso_address;
#endif
}
