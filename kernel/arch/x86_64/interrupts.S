;
; Copyright (c) 2016, 2017 Pedro Falcato
; This file is part of Onyx, and is released under the terms of the MIT License
; check LICENSE at the root directory for more information
;
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
extern signal_is_pending
extern lapic_send_eoi
irq_common:
	cld
	mov ax, ds
	push rax
	mov ax, 0x10
	mov ss, ax
	mov ds, ax
	mov es, ax
	mov rax, [rsp + 136]
	cmp rax, 0x8
	je .skip_swapgs
	swapgs
.skip_swapgs:
	call lapic_send_eoi
	mov rsi, rsp
	call irq_handler
	mov rsp, rax
	call signal_is_pending
	cmp rax, 1
	je .handle_signal
.continue:
	mov rax, [rsp + 136]
	cmp rax, 0x8
	je .skip_swapgs2
	swapgs
.skip_swapgs2:
	pop rax
	mov ds, ax
	mov es, ax
	popaq
	iretq
.handle_signal:
	mov rdi, rsp
	mov rsi, 0
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
	cld
	mov rax, ds
	push rax
	mov ax, 0x10
	mov ds, ax
	mov es, ax
	mov ss, ax
	mov rax, [rsp + 152]
	cmp rax, 0x8
	je .skip_swap
	swapgs
.skip_swap: 
	mov rdi, rsp
	call isr_handler
	call signal_is_pending
	cmp rax, 1
	je .isr_handle_signal
.isr_continue:
	mov rax, [rsp + 152]
	cmp rax, 0x8
	je .skip_swap2
	swapgs
.skip_swap2:
	pop rax
	mov ds, ax
	mov es, ax
	popaq
	add rsp, 16
	iretq
.isr_handle_signal:
	mov rdi, rsp
	mov rsi, 1
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
	mov rax, [rsp + 136]
	cmp rax, 0x8
	je .skip_swap_yield
	swapgs
.skip_swap_yield:
	call sched_switch_thread
	mov rsp, rax
	mov rax, [rsp + 136]
	cmp rax, 0x8
	je .skip_swap_yield2
	swapgs
.skip_swap_yield2:
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
global syscall_ENTRY64_int
extern syscall_list
extern SYSCALL_MAX_NUM
extern errno
section .data
global syscalls
syscalls: dq 0
section .text
syscall_ENTRY64_int:
	sti
	inc qword [syscalls]
	
	syscallsaveregs
	; load the kernel's segments
	mov cx, ds
	
	push rcx
	mov cx, 0x10
	mov ds, cx
	mov ss, cx
	mov es, cx

	mov rcx, [rsp + 136]
	cmp rcx, 0x8
	je .skip_swapgs_syscall
	swapgs 
.skip_swapgs_syscall:
	cmp rax, SYSCALL_MAX_NUM
	jl .syscall_exit_sig
	cmp rax, 10 ; If syscallnum == 10, it's a fork system call
	je .fork
.continue:
	call [syscall_list + rax * 8]
.syscall_exit:
	mov r11, [errno]
	mov rcx, [rsp + 136]
	cmp rcx, 0x8
	je .skip_swapgs_syscall2
	swapgs 
.skip_swapgs_syscall2:
	pop rcx
	mov ds, cx
	mov es, cx
	syscallpopregs
	iretq
.syscall_exit_sig:
	cli
	hlt
.fork:
	; Store relevant arguments to sys_fork and pass them in
	
	mov rdi, rsp

	jmp .continue 
global __sigret_return
__sigret_return:
	cli
	mov rsp, rdi
	swapgs
	pop rcx
	mov ds, cx
	mov es, cx
	popaq
	iretq
global apic_spurious_irq
apic_spurious_irq:
	iretq
