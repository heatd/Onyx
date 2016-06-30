; crt0.S - _start procedure. Initializes the C Library, calls main, calls exit(2)
section .text
global _start
extern init_libc
extern _init
extern main
extern exit
_start:
	; Setup end of stack frame linked list
	xor rbp, rbp
	push rbp
	push rbp
	mov rbp, rsp
	push rbp

	push rdi ; argc
	push rsi ; argv

	call init_libc ; Libc initialization

	call _init ; global constructors

	pop rsi
	pop rdi

	call main ; Call int main(int argc, char *argv[])

	mov rdi, rax ; use the main()'s return value for exit(2)

	call exit ; exit(2)
