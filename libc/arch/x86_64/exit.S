section .text

global exit
extern _fini
exit:
	push rdi
	call _fini
	pop rdi
	extern _exit
	call _exit
