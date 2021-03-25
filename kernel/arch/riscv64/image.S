/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
.section .boot

#include <onyx/image.h>

.global __cxa_atexit
__cxa_atexit:
	ret

.global _start
_start:
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
