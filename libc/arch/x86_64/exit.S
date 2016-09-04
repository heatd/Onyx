section .text

global exit
extern _fini
exit:

	call _fini

; Find a way to syscall. Right now I still need to fix handling on the kernel
; mov rax, SYSCALL_EXIT
; syscall
.Lhang:
	jmp .Lhang
