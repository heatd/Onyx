;
; Copyright (c) 2016, 2017 Pedro Falcato
; This file is part of Onyx, and is released under the terms of the MIT License
; check LICENSE at the root directory for more information
;
section .text
global return_from_execve:function
; Entry point is at RDI, argc at RSI, argv at RDX, envp at RCX, auxv at R8, stack at R9
return_from_execve:
	; Load the registers
	push rdi
	mov r11, 0x202
	mov rdi, rsi
	mov rsi, rdx
	mov rdx, rcx
	mov rcx, r8
	pop rcx
	; Reload unused registers to avoid leaks
	xor rbx, rbx
	xor rbp, rbp
	xor r10, r10
	xor r12, r12
	xor r13, r13
	xor r14, r14
	xor r15, r15
	; Load rsp
	mov rsp, r9
	xor r9, r9
	swapgs
	mov ax, 0x33
	mov ds, ax
	mov es, ax
	xor rax, rax
	o64 sysret
