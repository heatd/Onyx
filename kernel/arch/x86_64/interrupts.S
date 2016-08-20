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
	pushaq
	xor rdi,rdi   ;push dummy err code
	mov rsi, %1  ;push the interrupt number
	jmp isr_common ;Go to the handler
%endmacro
extern irq_handler
irq_common:
	mov ax, ds
	push rax
	mov ax, 0x10
	mov ss, ax
	mov ds, ax
	mov es, ax
	mov fs, ax
	mov gs, ax
	call irq_handler
	push rdi
	sub rdi, 32
	extern pic_send_eoi
	call pic_send_eoi
	pop rdi
	pop rax
	mov ds, ax
	mov es, ax
	mov fs, ax
	mov gs, ax
	popaq
	iretq

%macro IRQ 2
global irq%1
irq%1:
cli
pushaq
mov rdi, %2
jmp irq_common
%endmacro


%macro ISR_ERRCODE 1
global isr%1
isr%1:
	cli
	pop r15
	pushaq
	mov rdi, r15
	mov r15, [rsp]
	mov rsi, %1 ;push the interrupt number to the arguments
	jmp isr_common ;Go to the handler
%endmacro

extern isr_handler
global isr_common
isr_common:
	mov ax, ds
	push rax
	mov ax, 0x10
	mov ds, ax
	mov fs, ax
	mov gs, ax
	mov es, ax
	mov ss, ax
	call isr_handler

	pop rax
	mov ds,ax
	mov es,ax
	mov fs,ax
	mov gs,ax
	mov ss, ax
	popaq
	iretq

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
global irq0
irq0:
	cli
	pushaq
	; load the kernel's segments
	mov ax, ds
	push rax
	mov ax, 0x10
	mov ds, ax
	mov ss, ax
	mov fs, ax
	mov gs, ax
	mov es, ax
	extern timer_handler
	call timer_handler
	mov rdi, rsp
	extern sched_switch_thread
	call sched_switch_thread
	mov rsp, rax
	; reload segs
	pop rax
	mov ds, ax
	mov fs, ax
	mov gs, ax
	mov es, ax
	mov al, 0x20
	out 0x20, al
	popaq
	iretq

IRQ 1,33
IRQ 2,34
IRQ 3,35
IRQ 4,36
IRQ 5,37
IRQ 6,38
IRQ 7 ,39
IRQ 8 ,40
IRQ 9 ,41
IRQ 10 ,42
IRQ 11 ,43
IRQ 12 ,44
IRQ 13 ,45
IRQ 14 ,46
IRQ 15 ,47
global __syscall_int
extern syscall_list
extern SYSCALL_MAX_NUM
__syscall_int:
	cli
	; load the kernel's segments
	mov cx, ds
	push rcx
	mov cx, 0x10
	mov ds, cx
	mov ss, cx
	mov fs, cx
	mov gs, cx
	mov es, cx
	cmp rax, SYSCALL_MAX_NUM
	jl .exit
	call [syscall_list + rax * 8]
.exit:
	pop rcx
	mov ds, cx
	mov fs, cx
	mov gs, cx
	mov es, cx
	iretq
