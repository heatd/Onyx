.section .text
.macro pushaq
	push %rbx
	push %rcx
	push %rdx
	push %rdi
	push %rsi
	push %rbp
	push %r8
	push %r9
	push %r10
	push %r11
	push %r12
	push %r13
	push %r14
	push %r15
.endm
.macro popaq
	pop %r15
	pop %r14
	pop %r13
	pop %r12
	pop %r11
	pop %r10
	pop %r9
	pop %r8
	pop %rbp
	pop %rsi
	pop %rdi
	pop %rdx
	pop %rcx
	pop %rbx
.endm
.macro SAVE_SCRATCH_REGS
	push %rax
	push %rdi
	push %rsi
	push %rdx
	push %rcx
	push %r8
	push %r9
	push %r10
	push %r11
.endm
.macro RESTORE_SCRATCH_REGS
	pop %r11
	pop %r10
	pop %r9
	pop %r8
	pop %rcx
	pop %rdx
	pop %rsi
	pop %rdi
	pop %rax
.endm
.macro RESTORE_SCRATCH_REGS_NO_RAX
	pop %r11
	pop %r10
	pop %r9
	pop %r8
	pop %rcx
	pop %rdx
	pop %rsi
	pop %rdi
	add $8, %rsp
.endm

.global syscall_ENTRY64
syscall_ENTRY64:

	.cfi_startproc
	.cfi_register rip, rcx
	.cfi_return_column rcx
	.cfi_def_cfa_register rsp
	.cfi_def_cfa_offset 0

	cld
	swapgs
	# We can't preempt right now(unless we want chaos)!
	# Get the kernel stack, and save the user-stack
	mov %rsp, %gs:0x18
	mov %gs:0x10, %rsp

	# Save the registers
	pushaq
	# End the stack frame list
	xor %rbp, %rbp
	SAVE_SCRATCH_REGS
	mov %gs:0x18, %rdi
	call thread_store_ustack
	RESTORE_SCRATCH_REGS
	sti
	# Ah, we've saved the registers, and the user stack is safe - we can continue now(possible to preempt)
	# Save the old segments, and switch to the kernel ones
	mov %ds, %ecx
	push %rcx
	mov $0x10, %cx
	mov %cx, %ds
	mov %cx, %es

	# To conform to the Sys V ABI, we need to move r10 to rcx
	mov %r10, %rcx
	SAVE_SCRATCH_REGS 
	mov %rsp, %rdi
	mov %rax, %rsi
	add $72, %rdi
	call proc_event_enter_syscall
	RESTORE_SCRATCH_REGS
	# If the syscall is fork, setup pt_regs first
	cmp $10, %rax
	je .setup_fork
.continue_systemcall:
	push %rax
	# Setup the stack frame(the end of it anyway)
	push $0
	push %rbp
	mov %rsp, %rbp
	cmp (SYSCALL_MAX_NUM), %rax
	ja .invalid_syscall
	call *syscall_list(, %rax, 8)
.ret_from_syscall:
	pop %rbp
	add $8, %rsp

	SAVE_SCRATCH_REGS
	add $72, %rsp
	mov (%rsp), %rsi
	mov %rax, %rdi
	sub $72, %rsp
	call proc_event_exit_syscall
	RESTORE_SCRATCH_REGS

	cli

	add $8, %rsp

	pop %rcx
	mov %cx, %ds
	mov %cx, %es

	popaq
	SAVE_SCRATCH_REGS
	call thread_get_ustack
	mov %rax, %gs:0x18
	RESTORE_SCRATCH_REGS
	mov %gs:0x18, %rsp
	swapgs

	rex.w sysret
.setup_fork:
	mov %rsp, %rdi

	jmp .continue_systemcall
.invalid_syscall:
	mov $-38, %rax
	jmp .ret_from_syscall
.cfi_endproc

.extern AcpiEnterSleepState
.global __enter_sleep_state
__enter_sleep_state:
	# I'm sure this doesn't work, TODO
	# Okay, to do this we'll need to save every register
	# rax doesn't matter since we're using it to return a value anyway
	pushaq
	# Make sure to write everything to memory
	wbinvd
	# Enter the sleep state via assembly
	call AcpiEnterSleepState
	# In C this would be if(ACPI_FAILURE(st)) goto failure;
	cmp $0, %rax
	jne .failure
	# Woah, we're back from sleep
	# Restore registers and flush caches
.return:
	wbinvd
	popaq
	# Flush the TLB
	mov %cr3, %rdi
	mov %rdi, %cr3
	ret
.failure:
	mov $-1, %rax
	jmp .return
