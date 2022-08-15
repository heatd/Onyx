.global vfork
.type vfork,@function
vfork:
	pop %rdx
	mov $150,%eax
	syscall
	push %rdx
	mov %rax,%rdi
	.hidden __syscall_ret
	jmp __syscall_ret
