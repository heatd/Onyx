/*
 * Copyright (c) 2021 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_RISCV_PLATFORM_VM_LAYOUT_H
#define _ONYX_RISCV_PLATFORM_VM_LAYOUT_H

/* riscv virtual address space layout. Subsystem addresses are *offsets*,
 * not absolute addresses
 */

typedef enum
{
    arch_low_half_min = 0x10000,
    arch_brk_base = 0x80000000,
    arch_mmap_base = 0x0000550000000000,
    arch_low_half_max = 0x00007fffffffffff,
    arch_high_half = 0xffff800000000000, /* Default to this, but don't assume it */
    arch_vmalloc_off = 0x000000000000,
} vas_areas;

#define VM_VMALLOC_SIZE 0x100000000000

#define VMALLOC_ASLR_BITS 40
#define MMAP_ASLR_BITS    42
#define BRK_ASLR_BITS     30

#define VM_USER_ADDR_LIMIT   arch_low_half_max
#define VM_KERNEL_ADDR_LIMIT ((unsigned long) -1)

#define DEFAULT_USER_STACK_LEN (0x100000)

#define VM_HIGHER_HALF 0xffff800000000000

#endif
