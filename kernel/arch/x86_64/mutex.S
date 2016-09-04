section .text
global mutex_lock
mutex_lock:
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
global mutex_unlock
mutex_unlock:
	push rbp
	mov rbp, rsp
	xor rax, rax
	xchg [rdi], rax
	pop rbp
	ret