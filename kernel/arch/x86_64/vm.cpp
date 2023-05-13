/*
 * Copyright (c) 2017 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <cpuid.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <onyx/arch.h>
#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/vm.h>

static uintptr_t vm_calculate_virtual_address(uintptr_t bits)
{
    /* The bits reported by CPUID are 1-based */
    return -((uintptr_t) 1 << (bits - 1));
}

/* We don't support more than 48-bits(PML5) right now. */

#define VM_SUPPORTED_VM_BITS 48

void arch_vm_init(void)
{
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    assert(__get_cpuid(CPUID_ADDR_SPACE_SIZE, &eax, &ebx, &ecx, &edx) == 1);

    /* Layout of %eax: 7-0 Physical Addr bits implemented;
     * 16-8 Virtual Addr bits implemented, rest is reserved
     */
    uint8_t vm_bits = (uint8_t) (eax >> 8);

    vm_update_addresses(vm_calculate_virtual_address(vm_bits));
}

size_t arch_heap_get_size(void)
{
    return 0x200000000000;
}

/* TODO: Is this needed? */
size_t arch_get_initial_heap_size(void)
{
    return 0x400000;
}

/**
 * @brief Interpret mmap's hint and flags in an architecture-dependent way
 *
 * @param hint Hint passed to mmap (but sanitized!)
 * @param flags Flags given to mmap (but sanitized!)
 * @return Extra flags
 */
u64 arch_vm_interpret_mmap_hint_flags(void *hint, int flags)
{
    u64 extra = 0;
    unsigned long addr = (unsigned long) hint;

    // Emulate linux's behavior here and only search through the whole
    // address space if hint is > 47-bit
    if (addr > 0x00007fffffffffff)
        extra |= VM_FULL_ADDRESS_SPACE;
    return extra;
}

bool arch_vm_validate_mmap_region(unsigned long start, unsigned long size, u64 flags)
{
    // Check if we can indeed return this region
    if (start > 0x00007fffffffffff || start + size > 0x00007fffffffffff)
    {
        return flags & VM_FULL_ADDRESS_SPACE;
    }

    return true;
}
