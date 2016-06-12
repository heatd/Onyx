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
global __syscall_stub
__syscall_stub:
	cli
	pushaq
	extern syscall_handler
	call syscall_handler
	extern errno
	mov rbx, errno
	cmp rbx, 0
	jz .exit
	mov rax, errno
.exit:
	popaq
	sysexit

global __syscall
__syscall:
	mov ecx, 0xC0000081 ; STAR
	mov edx, 0x00080008
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
