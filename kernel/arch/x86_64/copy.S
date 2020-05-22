.section .text

.global __copy_non_temporal
.type __copy_non_temporal, @function
# __copy_non_temporal assumes that the buffers are properly aligned for the copy
# Failure to do so will result in worse performance
# __copy_non_temporal also assumes that the byte count is also aligned

# RDI holds destination buffer
# RSI holds source buffer
# RDX holds byte count
__copy_non_temporal:

prefetchnta (%rsi)

.loop:
	mov (%rsi), %rax
	movnti %rax, (%rdi)
	add $8, %rdi
	add $8, %rsi
	sub $8, %rdx

	jnz .loop

xor %rax, %rax

ret

.global __set_non_temporal
.type __set_non_temporal, @function
# __set_non_temporal assumes that the buffer is properly aligned for the memset
# Failure to do so will result in worse performance
# __set_non_temporal also assumes that the byte count is also aligned

# RDI holds destination buffer
# RSI holds byte value
# RDX holds byte count
__set_non_temporal:

# Since the byte value is probably not set up like we want it to,
# fill the register using the byte, so we can copy 8 bytes at a time

# Byte 0
mov %rsi, %r8
and $0xff, %r8
mov %r8, %rax
# Byte 1
shl $8, %r8
or %r8, %rax
# Byte 2
shl $8, %r8
or %r8, %rax
# Byte 3
shl $8, %r8
or %r8, %rax
# Byte 4
shl $8, %r8
or %r8, %rax
# Byte 5
shl $8, %r8
or %r8, %rax
# Byte 6
shl $8, %r8
or %r8, %rax
# Byte 7
shl $8, %r8
or %r8, %rax

.L0:
	movnti %rax, (%rdi)
	add $8, %rdi
	sub $8, %rdx

	jnz .L0

xor %rax, %rax

ret

.global memcpy
.type memcpy, @function
memcpy:
	push %rbp
	mov %rsp, %rbp

	mov %rdx, %rcx
	mov %rdi, %rax

	rep movsb

	pop %rbp

	ret

.global memset
.type memset, @function
memset:
	push %rbp
	mov %rsp, %rbp

	/* Shuffle the registers around, rep stosb requires count to be in %rcx, and the fill byte in %rax.
	 * We then use the freed-register %rsi to hold the return value, which is the address itself.
	 */
	mov %rdx, %rcx
	mov %rsi, %rax
	mov %rdi, %rsi

	rep stosb

	mov %rsi, %rax

	pop %rbp
	ret
