/*
* Copyright (c) 2020 - 2022 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
.section .text
.global __cxa_atexit
__cxa_atexit:
	li a0, 0
	ret

.section .boot
.align 16

stack_bottom:
.skip 4096

stack_top:

.skip 8

booted: .word 0

#include <onyx/image.h>

.global entry_point
.type entry_point,@function
entry_point:
	# Header time!
	j entry
	# Code 1 - unused
	.word 0
	.dword RISCV_LOAD_ADDRESS
	.dword __kernel_size
	.dword 0
	.word RISCV_HEADER_VERSION
	# Reserved 
	.word 0
	.dword 0
	.ascii RISCV_IMAGE_MAGIC
	.balign 4
	.ascii RISCV_IMAGE_MAGIC2
	# Reserved
	.word 0

entry:
.option push
.option norelax
	lla gp, __global_pointer$
.option pop

	mv s1, a1

	# Stop possible infinite loops of boots from happening
	lw t1, booted
	bnez t1, 2f

	li t1, 1
	sw t1, booted, t2

	lla sp, stack_top
	call early_paging_setup

	lla t0, boot_page_tables
	srli t1, t0, 12
	li t5, 9 << 60
	or t1, t1, t5

	csrw satp, t1
1:
	lla tp, percpu_base
	mv a0, s1
	lla ra, kernel_entry
	# Adjust the stack to point to a virtual address
	li t1, 0xffffffff00000000
	add sp, sp, t1
	ret
2:
	j 2b
