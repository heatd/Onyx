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
	mov rax, 7
	int 0x80
	pop rbp
	ret
global posix_spawn
posix_spawn:
	push rbp
	mov rbp, rsp
	mov rax, 9
	int 0x80
	pop rbp
	ret
global fork
fork:
	push rbp
	mov rbp, rsp
	push rdi
	push rsi
	push rdx
	mov rax, 10
	int 0x80
	pop rdx
	pop rsi
	pop rdi
	pop rbp
	ret
global _exit
_exit:
	push rbp
	mov rbp, rsp
	mov rax, 8
	int 0x80
	pop rbp
	ret
global mmap
mmap:
	push rbp
	mov rbp, rsp
	mov rax, 11
	int 0x80
	pop rbp
	ret
global munmap
munmap:
	push rbp
	mov rbp, rsp
	mov rax, 12
	int 0x80
	pop rbp
	ret
global mprotect
mprotect:
	push rbp
	mov rbp, rsp
	mov rax, 13
	int 0x80
	pop rbp
	ret
global mount
mount:
	push rbp
	mov rbp, rsp
	mov rax, 14
	int 0x80
	pop rbp
	ret
global close
close:
	push rbp
	mov rbp, rsp
	mov rax, 3
	int 0x80
	pop rbp
	ret