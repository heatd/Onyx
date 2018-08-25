.global __vdso_syscall
__vdso_syscall:
	mov %rdi, %rax
	mov %rsi, %rdi
	mov %rdx, %rsi
	mov %rcx, %rdx
	mov %r8, %r10	# r10 takes the place of rcx
	mov %r9, %r8
	syscall

	ret
