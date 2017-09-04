/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdint.h>
#include <stddef.h>
#include <cpuid.h>
#include <assert.h>
#include <stdio.h>

#include <onyx/compiler.h>
#include <onyx/vmm.h>
#include <onyx/cpu.h>

static uintptr_t vm_calculate_virtual_address(uintptr_t bits)
{
	/* The bits reported by CPUID are 1-based */
	return -((uintptr_t) 1 << (bits - 1));
}

void arch_vmm_init(void)
{
	unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
	assert(__get_cpuid(CPUID_ADDR_SPACE_SIZE, &eax, &ebx, &ecx, &edx) == 1);

	/* Layout of %eax: 7-0 Physical Addr bits implemented; 
	 * 16-8 Virtual Addr bits implemented, rest is reserved
	*/
	uint8_t vm_bits = (uint8_t) (eax >> 8);

	vm_update_addresses(vm_calculate_virtual_address(vm_bits));
}
