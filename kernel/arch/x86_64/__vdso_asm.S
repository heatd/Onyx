global __vdso_syscall
__vdso_syscall:
	mov rax, rdi
	mov rdi, rsi
	mov rsi, rdx
	mov rdx, rcx
	mov r10, r8	; r10 takes the place of rcx
	mov r8, r9
	syscall

	ret
