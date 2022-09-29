# __clone(func, stack, flags, arg, ptid, tls, ctid)
#           a0,    a1,    a2,  a3,   a4,  a5,   a6

# syscall(SYS_clone, flags, stack, ptid, tls, ctid)
#                a7     a0,    a1,   a2,  a3,   a4

.global __clone
.type  __clone, %function
__clone:
	li a7, 63
	ecall
	ret
