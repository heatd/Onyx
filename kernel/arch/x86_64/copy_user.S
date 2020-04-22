/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

# cbn_status_t copy_to_user(void *udst, const void *ksrc, size_t size);
.section .text
.global copy_to_user
.balign 32
copy_to_user:
	
	# Note: This is slow, but it's needed...
	# TODO: How can we access C structs from assembly safely?
	push %rdi
	push %rsi
	push %rdx

	call thread_get_addr_limit
	
	pop %rdx
	pop %rsi
	pop %rdi

	# Check if dst < addr_limit
	cmp %rax, %rdi
	# And if dst + len < addr_limit
	mov %rdi, %r8
	add %rdx, %r8
	cmp %rax, %r8

	ja copy_to_user.handler
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
	# Note: This is slow, but it's needed...
	# TODO: How can we access C structs from assembly safely?
	push %rdi
	push %rsi
	push %rdx

	call thread_get_addr_limit
	
	pop %rdx
	pop %rsi
	pop %rdi

	# Check if src < addr_limit
	cmp %rax, %rsi
	# And if src + len < addr_limit
	mov %rsi, %r8
	add %rdx, %r8
	cmp %rax, %r8

	ja copy_from_user.handler
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
	# Note: This is slow, but it's needed...
	# TODO: How can we access C structs from assembly safely?
	push %rdi

	call thread_get_addr_limit
	
	pop %rdi

	# Check if dst < addr_limit
	cmp %rax, %rdi

	ja strlen_user.handler

	# Store address limit in %r8

	mov %rax, %r8
	xor %rax, %rax
strlen_user.loop:
	cmp %r8, %rdi
	ja strlen_user.handler
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

.global get_user32
get_user32:
	# addr in %rdi, dest in %rsi, ret is 0 if good or -EFAULT if we faulted
	push %rdi
	push %rsi

	call thread_get_addr_limit

	pop %rsi	
	pop %rdi

	# Check if src < addr_limit
	cmp %rax, %rdi
	ja 3f
1:  movl (%rdi), %edx
	movl %edx, (%rsi)
	xor %rax, %rax
2:
	ret
3:
	mov $-14, %rax
	jmp 2b
.pushsection .ehtable
	.quad 1b
	.quad 3b
.popsection
