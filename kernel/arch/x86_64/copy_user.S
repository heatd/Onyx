/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#define kernel_min 0xffff800000000000
.section .data
kernel_min_val: .quad kernel_min

# cbn_status_t copy_to_user(void *udst, const void *ksrc, size_t size);
.section .text
.global copy_to_user
.balign 32
copy_to_user:
	cmp (kernel_min_val), %rdi
	jae copy_to_user.handler
	xor %rax, %rax
	mov %rdx, %rcx
copy_to_user.copy_instr:
	rep movsb (%rsi), (%rdi)
copy_to_user.function_out:
	ret
copy_to_user.handler:
	# CBN_STATUS_SEGFAULT = -5
	# These pieces of code were ported from Carbon but the principle applies
	# We're returning -EFAULT = -14
	mov $-14, %rax
	jmp copy_to_user.function_out

.pushsection .ehtable
	.quad copy_to_user.copy_instr
	.quad copy_to_user.handler
.popsection

# cbn_status_t copy_from_user(void *kdst, const void *usrc, size_t size);
.global copy_from_user
.balign 32
copy_from_user:
	cmp (kernel_min_val), %rsi
	jae copy_from_user.handler
	xor %rax, %rax
	mov %rdx, %rcx
copy_from_user.copy_instr:
	rep movsb (%rsi), (%rdi)
copy_from_user.function_out:
	ret
copy_from_user.handler:
	# CBN_STATUS_SEGFAULT = -5
	mov $-14, %rax
	jmp copy_from_user.function_out

.pushsection .ehtable
	.quad copy_from_user.copy_instr
	.quad copy_from_user.handler
.popsection

.global strlen_user
.balign 32
strlen_user:
	cmp (kernel_min_val), %rdi
	jae strlen_user.handler
	xor %rax, %rax
strlen_user.count:
	mov (%rdi), %si
	cmp $0, %si
	je strlen_user.function_out
	inc %rax
	inc %rdi
	jmp strlen_user.count
strlen_user.function_out:
	ret
strlen_user.handler:
	# CBN_STATUS_SEGFAULT = -5
	mov $-14, %rax
	jmp strlen_user.function_out

.pushsection .ehtable
	.quad strlen_user.count
	.quad strlen_user.handler
.popsection