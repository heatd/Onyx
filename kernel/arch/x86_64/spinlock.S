.section .text
.global spinlock_lock
spinlock_lock:
	push %rbp
	mov %rsp, %rbp
.L0:
	pause
	mov $1, %rax
	xchg %rax, (%rdi)
	cmp $1, %rax
	je .L0
	pop %rbp
	ret
.global spinlock_unlock
spinlock_unlock:
	push %rbp
	mov %rsp, %rbp
	xor %rax, %rax
	xchg %rax, (%rdi)
	pop %rbp
	ret
