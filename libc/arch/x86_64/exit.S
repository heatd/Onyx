.section .text

.global exit
.extern _fini
exit:
	push %rdi
	call *_fini@GOTPCREL(%rip)
	pop %rdi
	.extern _exit
	call *_exit@GOTPCREL(%rip)
