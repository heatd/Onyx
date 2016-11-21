;----------------------------------------------------------------------
; * Copyright (C) 2016 Pedro Falcato
; *
; * This file is part of Spartix, and is made available under
; * the terms of the GNU General Public License version 2.
; *
; * You can redistribute it and/or modify it under the terms of the GNU
; * General Public License version 2 as published by the Free Software
; * Foundation.
; *----------------------------------------------------------------------
section .text
%macro pushaq 0
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
%endmacro
%macro popaq 0
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
%endmacro
%macro ISR_NOERRCODE 1
global isr%1
isr%1:
	cli
	push 0 ;push dummy err code
	push %1 ;push the interrupt number
	pushaq
	jmp isr_common ;Go to the handler
%endmacro
extern irq_handler
extern handle_signal
extern current_process
irq_common:
	mov ax, ds
	push rax
	mov ax, 0x10
	mov ss, ax
	mov ds, ax
	mov es, ax
	extern lapic_send_eoi
	call lapic_send_eoi
	mov rsi, rsp
	call irq_handler
	mov rsp, rax
	mov rax, current_process
	cmp qword [rax], qword 0
	je .continue
	mov rax, [rax]
	cmp dword [rax], dword 1
	je .handle_signal
.continue:
	pop rax
	mov ds, ax
	mov es, ax
	popaq
	iretq
.handle_signal:
	call handle_signal
	jmp .continue
%macro IRQ 1
global irq%1
irq%1:
cli
pushaq
mov rdi, %1
jmp irq_common
%endmacro


%macro ISR_ERRCODE 1
global isr%1
isr%1:
	cli
	push %1 ;push the interrupt number to the intctx
	pushaq
	jmp isr_common ;Go to the handler
%endmacro

extern isr_handler
global isr_common
isr_common:
	mov ax, ds
	push rax
	mov ax, 0x10
	mov ds, ax
	mov es, ax
	mov ss, ax
	mov rdi, rsp
	call isr_handler
	mov rax, current_process
	cmp qword [rax], qword 0
	je .isr_continue
	mov rax, [rax]
	cmp dword [rax], dword 1
	je .isr_handle_signal
.isr_continue:
	pop rax
	mov ds,ax
	mov es,ax
	mov ss, ax
	popaq
	iretq
.isr_handle_signal:
	call handle_signal
	jmp .isr_continue
ISR_NOERRCODE 0
ISR_NOERRCODE 1
ISR_NOERRCODE 2
ISR_NOERRCODE 3
ISR_NOERRCODE 4
ISR_NOERRCODE 5
ISR_NOERRCODE 6
ISR_NOERRCODE 7
ISR_ERRCODE   8
ISR_NOERRCODE 9
ISR_ERRCODE   10
ISR_ERRCODE   11
ISR_ERRCODE   12
ISR_ERRCODE   13
ISR_ERRCODE   14
ISR_NOERRCODE 15
ISR_NOERRCODE 16
ISR_NOERRCODE 17
ISR_NOERRCODE 18
ISR_NOERRCODE 19
ISR_NOERRCODE 20
ISR_NOERRCODE 21
ISR_NOERRCODE 22
ISR_NOERRCODE 23
ISR_NOERRCODE 24
ISR_NOERRCODE 25
ISR_NOERRCODE 26
ISR_NOERRCODE 27
ISR_NOERRCODE 28
ISR_NOERRCODE 29
ISR_NOERRCODE 30
ISR_NOERRCODE 31
IRQ 0
IRQ 1
IRQ 2
IRQ 3
IRQ 4
IRQ 5
IRQ 6
IRQ 7
IRQ 8
IRQ 9
IRQ 10
IRQ 11
IRQ 12
IRQ 13
IRQ 14
IRQ 15
IRQ 16
IRQ 17
IRQ 18
IRQ 19
IRQ 20
IRQ 21
IRQ 22
IRQ 23
global _sched_yield
extern sched_switch_thread
_sched_yield:
	pushaq
	mov ax, ds
	push rax
	mov rdi, rsp
	call sched_switch_thread
	pop rax
	mov ds, ax
	mov es, ax
	popaq
	iretq
%macro syscallsaveregs 0
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi
	push rbp
	push r8
	push r9
	push r10
	push r12
	push r13
	push r14
	push r15
%endmacro
%macro syscallpopregs 0
	pop r15
	pop r14
	pop r13
	pop r12
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
%endmacro
global __syscall_int
extern syscall_list
extern SYSCALL_MAX_NUM
extern errno
section .data
; Forkstack, forkret, and forkretregs are dangerous.
; Rage condition waiting to happen...
global forkstack
forkstack: dq 0
global forkret
forkret: dq 0
global forkretregs
forkretregs: dq 0
section .text
__syscall_int:
	sti
	; load the kernel's segments
	syscallsaveregs
	mov cx, ds
	push rcx
	mov cx, 0x10
	mov ds, cx
	mov ss, cx
	mov es, cx
	cmp rax, SYSCALL_MAX_NUM
	jl .syscall_exit
	mov r10, [rsp + 104 + 8]
	mov r11, [rsp + 104 + 32]
	mov [forkstack], r11
	mov [forkret], r10
	mov [forkretregs], rsp
	call [syscall_list + rax * 8]
.syscall_exit:
	mov r11, errno
	pop rcx
	mov ds, cx
	mov es, cx
	syscallpopregs
	iretq
