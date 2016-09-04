section .text
global open
open:
	push rbp
	mov rbp, rsp
	mov rax, 2
	int 0x80
	pop rbp
	ret
global read
read:
	push rbp
	mov rbp, rsp
	mov rax, 1
	int 0x80
	pop rbp
	ret
global write
write:
	push rbp
	mov rbp, rsp
	mov rax, 0
	int 0x80
	pop rbp
	ret
global lseek
lseek:
	push rbp
	mov rbp, rsp
	mov rax, 8
	int 0x80
	pop rbp
	ret
global posix_spawn
posix_spawn:
	push rbp
	mov rbp, rsp
	mov rax, 10
	int 0x80
	pop rbp
	ret