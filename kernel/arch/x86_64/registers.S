;
; Copyright (c) 2016, 2017 Pedro Falcato
; This file is part of Onyx, and is released under the terms of the MIT License
; check LICENSE at the root directory for more information
;
section .text
global get_thread_ctx
get_thread_ctx:
	; Setup frame
	push rbp
	mov rbp, rsp
	; start saving segisters
	mov [rdi],rax
	mov [rdi + 8], rbx
	mov [rdi + 16], rcx
	mov [rdi + 24], rdx
	mov [rdi + 32], rdi
	mov [rdi + 40], rsi
	mov [rdi + 48], rsp
	mov [rdi + 56], rbp
	mov QWORD [rdi + 62], QWORD 0
	mov [rdi + 70], r8
	mov [rdi + 78], r9
	mov [rdi + 86], r10
	mov [rdi + 94], r11
	mov [rdi + 102], r12
	mov [rdi + 110], r13
	mov [rdi + 118], r14
	mov [rdi + 126], r15
	push rbp
	pushf
	pop rbp
	mov [rdi + 134], rbp
	pop rbp
	pop rbp
	ret
