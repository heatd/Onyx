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
%macro SAVE_SCRATCH_REGS 0
	push rax
	push rdi
	push rsi
	push rdx
	push rcx
	push r8
	push r9
	push r10
	push r11
%endmacro
%macro RESTORE_SCRATCH_REGS 0
	pop r11
	pop r10
	pop r9
	pop r8
	pop rcx
	pop rdx
	pop rsi
	pop rdi
	pop rax
%endmacro
%macro RESTORE_SCRATCH_REGS_NO_RAX 0
	pop r11
	pop r10
	pop r9
	pop r8
	pop rcx
	pop rdx
	pop rsi
	pop rdi
	add rsp, 8
%endmacro
extern syscall_list
extern syscall_helper
extern SYSCALL_MAX_NUM
extern do_irq_work
extern thread_store_ustack
extern thread_get_ustack
global syscall_ENTRY64:function
syscall_ENTRY64:
	cld
	swapgs
	; We can't preempt right now(unless we want chaos)!
	; Get the kernel stack, and save the user-stack
	mov qword[gs:0x18], rsp
	mov rsp, qword [gs:0x10]

	; Save the registers
	pushaq
	SAVE_SCRATCH_REGS
	mov rdi, qword[gs:0x18]
	call thread_store_ustack
	RESTORE_SCRATCH_REGS
	sti
	; Ah, we've saved the registers, and the user stack is safe - we can continue now(possible to preempt)
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
	; Setup the stack frame(the end of it anyway)
	push qword 0
	push rbp
	mov rbp, rsp
	cmp rax, [SYSCALL_MAX_NUM]
	ja .invalid_syscall
	call [syscall_list + rax * 8]
.ret_from_syscall:
	pop rbp
	add rsp, 8

	pop rcx
	mov ds, cx
	mov es, cx

	popaq
	cli
	SAVE_SCRATCH_REGS
	call thread_get_ustack
	mov qword[gs:0x18], rax
	RESTORE_SCRATCH_REGS
	mov rsp, qword[gs:0x18]
	swapgs

	o64 sysret
.setup_fork:
	mov rdi, rsp

	jmp .continue_systemcall
.invalid_syscall:
	mov rax, -38
	jmp .ret_from_syscall
extern AcpiEnterSleepState
global __enter_sleep_state
__enter_sleep_state:
	; I'm sure this doesn't work, TODO
	; Okay, to do this we'll need to save every register
	; rax doesn't matter since we're using it to return a value anyway
	pushaq
	; Make sure to write everything to memory
	wbinvd
	; Enter the sleep state via assembly
	call AcpiEnterSleepState
	cmp rax, 0			; In C this would be if(ACPI_FAILURE(st)) goto failure;
	jne .failure
	; Woah, we're back from sleep
	; Restore registers and flush caches
.return:
	wbinvd
	popaq
	; Flush the TLB
	mov rdi, cr3
	mov cr3, rdi
	ret
.failure:
	mov rax, -1
	jmp .return
