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
	.quad 0 /* flags */
	/* Reserved */
    .quad 0 
	.quad 0
	.quad 0
	.ascii ARM64_IMAGE_MAGIC
	.long 0

entry:
    wfi
    b entry

.align 16

stack_bottom:
.skip 4096

stack_top:
