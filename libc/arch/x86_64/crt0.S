# crt0.S - _start procedure. Initializes the C Library, calls main, calls exit(2)
.section .text
.global _start
.extern _init
.extern main
.extern exit
.extern _init_standard_libc
_start:
	# Setup end of stack frame linked list
	push %rbp
	mov %rsp, %rbp

	push %rdi # argc
	push %rsi # argv
	push %rdx # envp
	mov %rdx, %rdi # Pass envp to _init_standard_libc, so it can set environ
	call _init_standard_libc # Libc initialization

	call _init # global constructors
	
	pop %rdx
	pop %rsi
	pop %rdi
	call main # Call int main(int argc, char *argv[])

	mov %rax, %rdi # use the main()'s return value for exit(2)

	call exit # _exit(2)
