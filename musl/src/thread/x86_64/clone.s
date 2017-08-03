.text
.global __clone
.type   __clone,@function
__clone:
	mov $63, %rax
	syscall
	ret
