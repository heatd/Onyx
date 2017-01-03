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
global syscall_ENTRY64
syscall_ENTRY64:
	swapgs
	swapgs
	
	mov ax, 0x33
	mov ds, ax
	mov es, ax
	push ax
	push rsp
	push r11
	push 0x2b
	push rcx
	iretq