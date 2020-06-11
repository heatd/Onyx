.text
.global __clone
.hidden __clone
.type   __clone,@function

__clone:
	mov $63,%eax
	syscall
	ret
