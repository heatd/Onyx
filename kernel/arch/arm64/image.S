/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
.section .text
.global __cxa_atexit
__cxa_atexit:
    mov x0, 0
    ret

.section .boot, "ax"

#include <onyx/image.h>

.global entry_point
.type entry_point,@function
entry_point:
    /* Header time! */
    b entry
    /* Code 1 - unused */
    .quad 0
    .quad 0
    .quad __kernel_size
    .quad (1 << 3) /* flags. bit 3 = anywhere in physical memory, 2MB aligned */
    /* Reserved */
    .quad 0 
    .quad 0
    .quad 0
    .ascii ARM64_IMAGE_MAGIC
    .long 0

entry:
    mrs x9, sctlr_el1
    orr x9, x9, #(1 << 23) /* SPAN */
    orr x9, x9, #(1 << 12) /* Instruction cacheability */
    orr x9, x9, #(1 << 4)
    orr x9, x9, #(1 << 3) /* Alignment check for the stack at EL0 and 1 */
    orr x9, x9, #(1 << 2) /* Data cacheability */
    bic x9, x9, #(1 << 1) /* No alignment checking for data accesses at EL0 and 1 */
    msr sctlr_el1, x9
    adrp x1, stack_top
    add x1, x1, :lo12:stack_top
    mov sp, x1
    sub sp, sp, #16
    # Save the device tree
    str x0, [sp, #-16]
    adrp x0, boot_page_tables
    add x0, x0, :lo12:boot_page_tables
    # Get the load address (PC-relative adrp to the head of the kernel image)
    adrp x1, entry_point
    add x1, x1, :lo12:entry_point

    # Invalidate the TLB before setting it up
    tlbi    vmalle1is
    dsb     sy
    isb

    bl arm64_setup_mmu
    ldr x6, =.mmu_enabled
    blr x6
.mmu_enabled:
    ldr x0, [sp, #-16]
    # Use the virtual address of the stack
    ldr x1, =stack_top
    mov sp, x1

    ldr x1, =percpu_base
    msr tpidr_el1, x1

    // XXX(pedro): fix
    mrs    x1, cpacr_el1
    mov    x2, #(3 << 20)
    orr    x2, x1, x2
    msr    cpacr_el1, x2

    bl kernel_entry

    bl runtime_call_constructors
	# x0 = cpu nr
	mov x0, xzr
	bl init_ssp_for_cpu

	bl kernel_main

.wait:
    wfi
    b .wait

.balign 16

.section .bss
.balign 16
stack_bottom:
.skip 8192
stack_top:
