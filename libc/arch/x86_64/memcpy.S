.section .text

.global memcpy
memcpy:
	push %rbp
	mov %rbp, %rsp

	mov %rdx, %rcx

	rep movsb

	pop %rbp

	ret