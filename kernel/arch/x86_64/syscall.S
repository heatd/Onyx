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
section .bss
user_stack: resq 1
section .text
global __syscall_stub
__syscall_stub:
	cli
	extern tss
	mov [user_stack], rsp
	; First thing we need to do is get the kernel stack from the tss
	; so we know it's safe
	mov rsp, [tss + 4]
	; Save the return register
	push r11
	push rcx
	mov rcx, r10
	extern syscall_handler
	call syscall_handler
	pop rcx
	pop r11
	mov rsp, [user_stack]
	o64 sysret

global __syscall
__syscall:
	mov ecx, 0xC0000081 ; STAR
	mov rdx, 0x00080008
	xor eax, eax
	wrmsr
	mov ecx, 0xC0000082 ;LSTAR
	mov rax, __syscall_stub
	mov rdx, rax
	shr rdx, 32
	wrmsr
	mov ecx, 0xC0000084
	xor eax, eax
	wrmsr
	ret
