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

.section .boot

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
    wfi
    b entry

.balign 16

stack_bottom:
.skip 4096

stack_top:
