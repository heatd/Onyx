.global __unmapself
.type __unmapself, %function
__unmapself:
	li a7, 12 # SYS_munmap
	ecall
	li a7, 64  # SYS_exit
	ecall
