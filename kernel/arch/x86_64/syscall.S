section .text
%macro pushaq 0
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
%endmacro
extern syscall_list
extern syscall_helper
extern SYSCALL_MAX_NUM
global syscall_ENTRY64
syscall_ENTRY64:
	cld
	swapgs
	; Get the kernel stack, and save the user-stack
	mov qword[gs:0x18], rsp
	mov rsp, qword [gs:0x10]
	sti
	; Save the registers
	pushaq
	; Save the old segments, and switch to the kernel ones

	mov ecx, ds
	push rcx
	mov cx, 0x10
	mov ds, cx
	mov es, cx

	; To conform to the Sys V ABI, we need to move r10 to rcx
	mov rcx, r10
	
	; If the syscall is fork, setup pt_regs first
	cmp rax, 10
	je .setup_fork
.continue_systemcall:
	cmp rax, [SYSCALL_MAX_NUM]
	jg .invalid_syscall
	call [syscall_list + rax * 8]

	pop rcx
	mov ds, cx
	mov es, cx

	popaq
	cli
	mov rsp, qword[gs:0x18]
	swapgs

	o64 sysret
.setup_fork:
	mov rdi, rsp

	jmp .continue_systemcall
.invalid_syscall:
	cli
	hlt