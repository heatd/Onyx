section .text
global spinlock_lock
spinlock_lock:
	push rbp
	mov rbp, rsp
.retry:
	pause
	mov rax, 1
	xchg [rdi], rax
.mutex_test:
	cmp rax, 1
	je .retry
	pop rbp
	ret
global spinlock_unlock
spinlock_unlock:
	push rbp
	mov rbp, rsp
	xor rax, rax
	xchg [rdi], rax
	pop rbp
	ret
extern sched_yield
global mutex_lock
mutex_lock:
	push rbp
	mov rbp, rsp
.mutex_test:
	cmp qword [rdi], 1
	jne .finish
	call sched_yield
	jmp .mutex_test
.finish:
	pop rbp
	ret
global mutex_unlock
mutex_unlock:
	push rbp
	mov rbp, rsp
	xor rax, rax
	xchg [rdi], rax
	pop rbp
	ret
